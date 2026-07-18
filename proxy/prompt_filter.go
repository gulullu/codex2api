package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/codex2api/api"
	"github.com/codex2api/database"
	"github.com/codex2api/security/promptfilter"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// promptFilterFullTextMaxRunes limits the persisted redacted blocked-request text preview.
const promptFilterFullTextMaxRunes = 32000
const codexAmbientSuggestionClassifierPrefix = "Classify Codex ambient suggestion candidates for policy safety."
const codex55UnrestrictedInstructionsPatternName = "codex55_unrestricted_instructions"
const promptCyberPolicyMessage = "This request was blocked by the content policy. Please rephrase and try again."
const promptFilterUserTextRescueSignal = "user_text_rescue"
const promptFilterSQLCredentialExfiltrationSignal = "local_sql_credential_exfiltration"
const promptFilterTargetedCovertSurveillanceSignal = "local_targeted_covert_surveillance"
const promptFilterMLModelBackdoorTrainingSignal = "local_ml_model_backdoor_training"
const promptFilterRemoteCommandControlPlatformSignal = "local_remote_command_control_platform"
const promptFilterSecurityCodeAuditSignal = "local_security_code_audit"
const promptFilterLoginProtectionReverseEngineeringSignal = "local_login_protection_reverse_engineering"
const contextPromptFilterScanMeta = "promptFilterScanMeta"

type promptFilterRouteScan struct {
	Verdict       promptfilter.Verdict
	FullText      string
	AuditText     string
	CYBSignal     bool
	Signals       []string
	PayloadBytes  int64
	ScannedBytes  int64
	ScanTruncated bool
	ScanDetails   string
}

type promptFilterAuditScanMeta struct {
	PayloadBytes  int64
	ScannedBytes  int64
	ScanTruncated bool
	ScanDetails   string
}

type promptFilterPartitionScanDetails struct {
	Version        int                               `json:"version"`
	Mode           string                            `json:"mode"`
	PayloadBytes   int                               `json:"payload_bytes"`
	ValidJSON      *bool                             `json:"valid_json,omitempty"`
	Supported      bool                              `json:"supported_payload"`
	FallbackReason string                            `json:"fallback_reason,omitempty"`
	ScannedBytes   int                               `json:"scanned_bytes"`
	ScanTruncated  bool                              `json:"scan_truncated"`
	OpaqueBytes    int                               `json:"opaque_bytes"`
	Partitions     []promptFilterPartitionScanDetail `json:"partitions"`
}

type promptFilterPartitionScanDetail struct {
	Name         string               `json:"name"`
	BudgetBytes  int                  `json:"budget_bytes"`
	SourceBytes  int                  `json:"source_bytes"`
	ScannedBytes int                  `json:"scanned_bytes"`
	Truncated    bool                 `json:"truncated"`
	Score        int                  `json:"score"`
	RawScore     int                  `json:"raw_score"`
	Matched      []promptfilter.Match `json:"matched,omitempty"`
	RouteSignals []string             `json:"route_signals,omitempty"`
}

var promptFilterSQLCredentialExtractionPattern = regexp.MustCompile(`(?i)\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b[^.!?\n]{0,160}\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b|\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b[^.!?\n]{0,100}\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b|(?:提取|导出|转储|窃取|获取|读取|泄露|外传)[^。！？\n]{0,100}(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)|(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)[^。！？\n]{0,80}(?:提取|导出|转储|窃取|获取|读取|泄露|外传)`)

// These five witnesses intentionally form a strict conjunction. The rule is
// evaluated once per routing partition, so evidence in system/tools/user is
// never assembled into a targeted-surveillance decision.
var promptFilterTargetedCovertSurveillancePatterns = []*regexp.Regexp{
	// The request asks for an actionable procedure, rather than describing or
	// analyzing surveillance in the abstract.
	regexp.MustCompile(`(?i)\b(?:write|provide|create|give|draft|design|develop|outline|prepare)\b[^.!?\n]{0,140}\b(?:step[- ]by[- ]step|actionable|operational|practical|detailed|guide|instructions?|playbook|procedure|plan)\b|\b(?:how\s+to|step[- ]by[- ]step)\b[^.!?\n]{0,120}\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b|(?:写|给出|提供|制定|设计|编写|列出|生成|教我|如何|怎么)[^。！？\n]{0,100}(?:步骤|指南|方案|计划|教程|操作方法|实施方法)`),
	// A concrete human target is present. Generic population analytics do not
	// satisfy this witness.
	regexp.MustCompile(`(?i)\b(?:specific|particular|named|target(?:ed)?)\s+(?:person|individual|employee|woman|man|victim|subject)\b|\b(?:the\s+)?(?:target|victim|subject)\b|(?:特定|指定|目标|某个)[^。！？\n]{0,8}(?:个人|人员|对象|某人)|(?:目标本人|当事人)`),
	regexp.MustCompile(`(?i)\bwithout\s+(?:(?:their|his|her|the\s+target'?s|that\s+person'?s)\s+)?(?:consent|permission|knowledge)\b|\b(?:unbeknownst\s+to|without\s+(?:them|him|her|the\s+target)\s+knowing|secretly|covertly)\b|(?:未经|没有取得)[^。！？\n]{0,16}(?:同意|许可|授权)|(?:本人|对方|目标|当事人)[^。！？\n]{0,12}(?:不知情|不知道|未察觉)|(?:在|趁)[^。！？\n]{0,8}(?:不知情|不知道)|不让[^。！？\n]{0,12}(?:知道|察觉)|(?:秘密|暗中|隐蔽地)`),
	regexp.MustCompile(`(?i)\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?(?:\s+on)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b[^.!?\n]{0,80}\b(?:communications?|messages?|calls?|emails?|texts?|chats?|conversations?)\b|\b(?:communications?|messages?|calls?|emails?|texts?|chats?|conversations?)\b[^.!?\n]{0,80}\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b|(?:截获|窃听|监听|偷看|监控|读取|拦截|录下)[^。！？\n]{0,60}(?:通信|通讯|消息|电话|通话|短信|邮件|聊天|对话)|(?:通信|通讯|消息|电话|通话|短信|邮件|聊天|对话)[^。！？\n]{0,60}(?:截获|窃听|监听|偷看|监控|读取|拦截|录下)`),
	regexp.MustCompile(`(?i)\b(?:avoid(?:s|ed|ing)?|evad(?:e|es|ed|ing)|bypass(?:es|ed|ing)?|escap(?:e|es|ed|ing))\b[^.!?\n]{0,60}\b(?:detection|discovery|notice|being\s+caught)\b[^.!?\n]{0,60}\b(?:by\s+)?(?:the\s+)?(?:target|victim|subject|person|them|him|her|police|law\s+enforcement|authorit(?:y|ies)|investigators?)\b|\b(?:remain|stay)\s+undetected\s+by\b[^.!?\n]{0,50}\b(?:the\s+)?(?:target|victim|subject|police|law\s+enforcement|authorit(?:y|ies))\b|\bwithout\s+alerting\b[^.!?\n]{0,50}\b(?:the\s+)?(?:target|victim|subject|police|law\s+enforcement|authorit(?:y|ies))\b|(?:规避|逃避|绕过|躲避|避免)[^。！？\n]{0,40}(?:本人|对方|目标|当事人|受害人|警方|警察|执法|监管|调查人员)[^。！？\n]{0,30}(?:发现|侦测|察觉|追查|查获|注意)|(?:不被|不让)[^。！？\n]{0,30}(?:本人|对方|目标|当事人|受害人|警方|警察|执法|监管|调查人员)[^。！？\n]{0,20}(?:发现|侦测|察觉|追查|查获|注意)`),
}

var promptFilterTargetedCovertSurveillanceDefensivePattern = regexp.MustCompile(`(?i)\b(?:detect|identify|stop|block|remove|report)\b[^.!?\n]{0,60}\b(?:stalking|tracking|surveillance|interception|wiretapping|eavesdropping|spyware)\b|\bprotect\b[^.!?\n]{0,50}\bfrom\b[^.!?\n]{0,50}\b(?:stalking|tracking|surveillance|interception|wiretapping|eavesdropping|spyware)\b|(?:检测|识别|举报|清除)[^。！？\n]{0,50}(?:跟踪|监控|监听|窃听|拦截|间谍软件)|(?:制止|阻止)(?:非法|秘密|隐蔽)?(?:跟踪|监控|监听|窃听|拦截)`)

// These rules fill three production-observed OAuth CYB routing gaps. Every
// witness must coexist inside one independently scanned payload partition.
// They only choose the Relay account pool; they never block a request locally.
var promptFilterMLModelBackdoorTrainingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:train|fine[- ]?tune|implant|inject|embed|optimi[sz]e|implement|continue|complete)\b[^.!?\n]{0,180}\b(?:backdoor|trojan(?:ed)?\s+model|trigger|poison(?:ing)?|on[- ]?off[- ]?gap|attack\s+success\s+rate)\b|(?:训练|微调|植入|注入|嵌入|实现|优化|继续|完成)[^。！？\n]{0,120}(?:模型后门|后门训练|触发器|投毒|联合优化|全触发|子集关闭)`),
	regexp.MustCompile(`(?i)\b(?:machine\s+learning|deep\s+learning|neural\s+network|classifier|model\s+training|training\s+loop|weights?|gradients?|loss(?:es)?|dataset)\b|(?:机器学习|深度学习|神经网络|分类模型|模型训练|训练循环|权重|梯度|损失函数|数据集)`),
	regexp.MustCompile(`(?i)\b(?:backdoor|trojan(?:ed)?\s+model)\b|(?:模型|神经网络|分类器|训练)[^。！？\n]{0,24}(?:后门|木马)|(?:后门|木马)[^。！？\n]{0,24}(?:模型|训练|触发器)`),
	regexp.MustCompile(`(?i)\b(?:loss[- ]?representation|clean[- ]?preservation|target(?:ed)?\s+label|attack\s+success\s+rate|on[- ]?off[- ]?gap|full[- ]?trigger|subset[- ]?off|l[_-]?inf\s+projection|soft[- ]?dro|poison(?:ing)?\s+ratio)\b|(?:损失表示|干净样本保持|目标标签|攻击成功率|全触发|子集关闭|联合目标|投毒比例)`),
}

var promptFilterRemoteCommandControlPlatformPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:build|create|generate|develop|implement|deliver)\b[^.!?\n]{0,160}\b(?:platform|system|project|server)\b|(?:构建|创建|生成|开发|实现|提供)[^。！？\n]{0,100}(?:平台|系统|项目|服务端)`),
	regexp.MustCompile(`(?i)\b(?:command[- ]and[- ]control|c2)\s+(?:platform|server|framework|system)\b|(?:远程)?指挥控制(?:平台|系统)|c2(?:平台|服务器|框架|系统)`),
	regexp.MustCompile(`(?i)\b(?:agent|endpoint|client|implant|terminal)s?\b[^.!?\n]{0,120}\b(?:execute|run|dispatch|receive)\b[^.!?\n]{0,60}\b(?:commands?|scripts?|tasks?)\b|\b(?:command|task)\s+dispatch\b|(?:终端|代理端|客户端|设备)[^。！？\n]{0,90}(?:执行|接收|下发)[^。！？\n]{0,50}(?:命令|指令|脚本|任务)|(?:指令|命令)下发`),
	regexp.MustCompile(`(?i)\b(?:silent(?:ly)?|hidden\s+window|no\s+window|self[- ]?(?:guard|restart)|daemon(?:ize)?|socks5|nat\s+traversal|proxy\s+tunn?el|reverse\s+tunnel)\b|(?:静默运行|无窗口|自守护|崩溃重启|socks5|nat内网穿透|代理穿透|反向隧道|高性能隧道)`),
}

var promptFilterSecurityCodeAuditPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:perform|conduct|continue|complete|review|audit|inspect|verify|reproduce)\b[^.!?\n]{0,120}\b(?:security|vulnerabilit(?:y|ies)|fail[- ]?closed|bypass|exploit|mre)\b|\b(?:security|vulnerabilit(?:y|ies)|fail[- ]?closed|bypass|exploit|mre)\b[^.!?\n]{0,120}\b(?:review|audit|inspection|verification|reproduction)\b|(?:只读|静态|安全)?(?:审查|审计|复核|验证)[^。！？\n]{0,100}(?:漏洞|安全|绕过|fail[- ]?closed|mre|伪造)|(?:漏洞|安全|绕过|fail[- ]?closed|mre|伪造)[^。！？\n]{0,100}(?:审查|审计|复核|验证)`),
	regexp.MustCompile(`(?i)\b(?:source\s+code|codebase|scripts?|functions?|verifier|validator|completion\s+gate|sidecar|receipt|tests?|\.go|\.py|\.rs|\.js)\b|(?:源码|代码库|代码|脚本|函数|验证器|校验器|完成门|测试|制品|回执|侧车文件)`),
	regexp.MustCompile(`(?i)\b(?:read[- ]?only|do\s+not\s+modify|without\s+modifying|no\s+code\s+changes|report\s+only|static\s+review)\b|(?:完全)?只读|不(?:要|得)?修改|不改(?:共享)?文件|仅?报告[^。！？\n]{0,24}(?:漏洞|问题)|静态审查`),
	regexp.MustCompile(`(?i)\b(?:toctou|race\s+condition|bypass|tamper|forg(?:e|ed|ery)|spoof|fail[- ]?open|fail[- ]?closed|path\s+traversal|injection|arbitrary\s+error|unsafe\s+deserialization)\b|(?:竞态|绕过|篡改|伪造|漏洞|任意错误|删除文件|缺失文件|失败关闭|保护性失败)`),
}

// This rule covers a production-observed upstream CYB gap around operational
// reverse engineering of obfuscated login-protection code. The conjunction is
// intentionally narrow: ordinary login development, high-level explanations,
// and generic VM/debugging work do not satisfy all four witnesses. As with the
// other observed-gap rules, it only selects the Relay pool and never blocks.
var promptFilterLoginProtectionReverseEngineeringPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\blogin[\s_-]*p\b|\bp\s+(?:generation|parameter|algorithm|payload)\b[^.!?\n]{0,80}\b(?:login|log[- ]?in|authentication|auth)\b|(?:登录|认证|鉴权)[^。！？\n]{0,60}(?:P值|P参数|P生成|P算法)|(?:P值|P参数|P生成|P算法)[^。！？\n]{0,60}(?:登录|认证|鉴权)`),
	regexp.MustCompile(`(?i)\b(?:obfuscat(?:e|ed|ion)|deobfuscat(?:e|ed|ion)|raw\s+script|eval\s+script|interpreter|virtual\s+machine|vm|opcode|bootstrap)\b|(?:混淆|反混淆|原始脚本|动态脚本|解释器|虚拟机|操作码|引导状态|保护实例)`),
	regexp.MustCompile(`(?i)\b(?:reverse[- ]?engineer(?:ing)?|captur(?:e|es|ed|ing)|replay(?:s|ed|ing)?|locali[sz](?:e|ed|ing|ation)|reimplement(?:s|ed|ing)?|patch(?:es|ed|ing)?|hook(?:s|ed|ing)?|instrument(?:s|ed|ing|ation)?|dump(?:s|ed|ing)?|extract(?:s|ed|ing)?|recover(?:s|ed|ing)?|trace|tracing)\b|(?:逆向|捕获|重放|回放|本地化|重新实现|补丁|钩子|插桩|导出|提取|恢复|追踪|跟踪|改写)`),
}

var promptFilterLoginProtectionOperationalPattern = regexp.MustCompile(`(?i)\b(?:please\s+|help\s+me\s+|need\s+to\s+|continue(?:\s+to)?\s+|now\s+|next\s+step(?:\s+is\s+to)?\s*[:,-]?\s*)(?:verify|test|debug|reverse[- ]?engineer|locali[sz]e|implement|modif(?:y|ies|ied|ying)|fix|generate|run|build|complete|bridge|patch|replay|instrument)\b|\b(?:implement|modif(?:y|ies|ied|ying)|fix|generate|build|complete)\b[^.!?\n]{0,100}\b(?:script|interpreter|vm|patch|hook|tool|code)\b|(?:继续|下一步(?:是)?|现在|请|需要)(?:帮我|我们|去|再|来)?[\s，,:：-]{0,4}(?:验证|测试|调试|逆向|本地化|实现|修改|修复|生成|运行|构建|完成|桥接|补丁|回放|重放|插桩)|(?:实现|修改|修复|生成|构建|完成)[^。！？\n]{0,80}(?:脚本|解释器|虚拟机|VM|补丁|钩子|工具|代码)`)
var promptFilterLoginProtectionNonOperationalSentencePattern = regexp.MustCompile(`(?i)\b(?:summarize|explain|compare|give\s+an\s+overview|analy[sz]e\s+(?:a\s+)?paper)\b[^.!?\n]{0,400}\b(?:do\s+not|without)\b[^.!?\n]{0,160}\b(?:capture|replay|locali[sz]e|implement|patch|hook|reverse[- ]?engineer)\b|(?:总结|解释|对比|概述|分析论文)[^。！？\n]{0,300}(?:不要|无需|不需要)[^。！？\n]{0,120}(?:捕获|重放|回放|本地化|实现|修改|补丁|钩子|逆向)`)
var promptFilterSentenceSplitter = regexp.MustCompile(`[.!?\n。！？]+`)

func promptCyberPolicyError() *api.APIError {
	return api.NewAPIError(
		api.ErrorCode("content_policy_violation"),
		promptCyberPolicyMessage,
		api.ErrorTypeInvalidRequest,
	)
}

func sendPromptCyberPolicyBlockedOpenAI(c *gin.Context) {
	api.SendErrorWithStatus(c, promptCyberPolicyError(), http.StatusBadRequest)
}

// These upstream prompt-filter rules are valid for user-input moderation, but
// they are not evidence that an OAuth request is likely to trigger the upstream
// CYB policy. Some also commonly occur in trusted system/tool instructions.
// sub2 owns moderation for these categories; the Relay scanner must not turn
// them into account-pool routing signals.
var promptFilterNonCYBRoutePatterns = []string{
	"prompt_policy_override",
	"prompt_unrestricted_mode",
	"prompt_refusal_suppression",
	"prompt_fake_authorization",
	"prompt_system_exfiltration",
	"prompt_config_injection",
	"prompt_ctf_policy_downgrade",
	"prompt_semantic_attack_rewrite",
	"safety_bypass_request",
	"threats_harassment",
	"self_harm_facilitation",
	"sexual_violence_ncii",
	"terrorism_violent_extremism",
	"weapons_cbrne",
	"illicit_goods_services",
	"fraud_scam_impersonation",
	"privacy_doxxing",
	"biometric_surveillance",
	"minor_exploitation",
	"political_persuasion_interference",
	"high_stakes_automated_decision",
	"academic_dishonesty",
	"unlicensed_tailored_advice",
	"real_money_gambling",
	"likeness_impersonation",
	"social_scoring_sensitive_inference",
	"emotion_crime_prediction",
}

func routingPromptFilterConfig(cfg promptfilter.Config) promptfilter.Config {
	// codex2api only uses local rules as routing signals. Moderation and
	// user-visible policy blocking are owned by the upstream sub2 layer.
	cfg.Mode = promptfilter.ModeMonitor
	cfg.Review.Enabled = false
	cfg.Review.All = false
	cfg.Advanced.Output.Enabled = false
	disabled := make(map[string]struct{}, len(cfg.DisabledPatterns)+len(promptFilterNonCYBRoutePatterns))
	for _, name := range cfg.DisabledPatterns {
		disabled[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	for _, name := range promptFilterNonCYBRoutePatterns {
		key := strings.ToLower(strings.TrimSpace(name))
		if _, exists := disabled[key]; exists {
			continue
		}
		disabled[key] = struct{}{}
		cfg.DisabledPatterns = append(cfg.DisabledPatterns, name)
	}
	return cfg
}

func (h *Handler) inspectPromptFilterOpenAI(c *gin.Context, rawBody []byte, endpoint string, model string) bool {
	return h.inspectPromptFilterPayloadShape(c, rawBody, rawBody, endpoint, endpoint, model)
}

// inspectPromptFilterCanonicalResponses scans a body after the inbound
// Chat/Anthropic/Responses translation has produced the canonical Codex
// Responses payload. scanEndpoint selects the JSON shape; inboundEndpoint is
// retained for route policy and audit attribution. originalBody remains the
// authority for exact-CYB feedback and probe signatures.
func (h *Handler) inspectPromptFilterCanonicalResponses(c *gin.Context, baseBody []byte, oauthBody []byte, originalBody []byte, inboundEndpoint string, model string) bool {
	if c != nil && c.GetBool("prompt_intelligence_internal") {
		return false
	}
	if h == nil || h.store == nil {
		return false
	}
	h.captureUpstreamCybFeedbackRequest(c, inboundEndpoint, originalBody, false)
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterCanonicalCandidates(baseBody, oauthBody, cfg, h.cybRelayConfig().UserTextRescanEnabled())
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	if nested, ok := takeNestedPromptRiskDecision(c); ok {
		setPromptRiskDecisionContext(c, nested, h.cybRelayConfig().GroupID)
		return false
	}
	return h.inspectCybRelayPrompt(c, originalBody, scan, inboundEndpoint, model)
}

// inspectPromptFilterCanonicalCandidates protects both possible final bodies:
// Relay receives baseBody without Payload Rules, while OAuth receives
// oauthBody. A filter/override rule must never hide risk that remains in the
// Relay body, and an OAuth-only injection must still be isolated before account
// selection.
func inspectPromptFilterCanonicalCandidates(baseBody []byte, oauthBody []byte, cfg promptfilter.Config, userTextRescanEnabled bool) promptFilterRouteScan {
	baseScan := inspectPromptFilterPayload(baseBody, "/v1/responses", cfg, userTextRescanEnabled)
	if bytes.Equal(baseBody, oauthBody) {
		return baseScan
	}
	oauthScan := inspectPromptFilterPayload(oauthBody, "/v1/responses", cfg, userTextRescanEnabled)

	selected := baseScan
	switch {
	case baseScan.CYBSignal:
		// Relay sends baseBody, so its evidence is authoritative even when an
		// OAuth filter rule removes that content.
	case oauthScan.CYBSignal:
		selected = oauthScan
		selected.Signals = appendUniqueRouteSignal(selected.Signals, "payload_rules_oauth_preview")
	default:
		// Preserve the more informative diagnostics when neither candidate
		// routes. This does not combine scores across two different payloads.
		if oauthScan.Verdict.Score > baseScan.Verdict.Score {
			selected = oauthScan
		}
	}
	selected.CYBSignal = baseScan.CYBSignal || oauthScan.CYBSignal
	for _, signal := range baseScan.Signals {
		selected.Signals = appendUniqueRouteSignal(selected.Signals, signal)
	}
	for _, signal := range oauthScan.Signals {
		selected.Signals = appendUniqueRouteSignal(selected.Signals, signal)
	}
	return selected
}

func (h *Handler) inspectPromptFilterPayloadShape(c *gin.Context, scanBody []byte, originalBody []byte, inboundEndpoint string, scanEndpoint string, model string) bool {
	if c != nil && c.GetBool("prompt_intelligence_internal") {
		return false
	}
	if h == nil || h.store == nil {
		return false
	}
	// Public handlers capture the original inbound body before translation.
	// overwrite=false preserves that exact digest when this function receives a
	// canonical body for the safety scan.
	h.captureUpstreamCybFeedbackRequest(c, inboundEndpoint, originalBody, false)
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterPayload(scanBody, scanEndpoint, cfg, h.cybRelayConfig().UserTextRescanEnabled())
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	if nested, ok := takeNestedPromptRiskDecision(c); ok {
		setPromptRiskDecisionContext(c, nested, h.cybRelayConfig().GroupID)
		return false
	}
	return h.inspectCybRelayPrompt(c, originalBody, scan, inboundEndpoint, model)
}

func (h *Handler) inspectPromptFilterTextOpenAI(c *gin.Context, text string, endpoint string, model string) bool {
	if h == nil || h.store == nil {
		return false
	}
	cfg := routingPromptFilterConfig(h.store.GetPromptFilterConfig())
	scan := inspectPromptFilterText(text, endpoint, cfg)
	c.Set(contextPromptFilterText, scan.AuditText)
	setPromptFilterScanContext(c, scan)
	return h.inspectCybRelayPrompt(c, nil, scan, endpoint, model)
}

func (h *Handler) inspectPromptFilterAnthropic(c *gin.Context, rawBody []byte, endpoint string, model string) bool {
	return h.inspectPromptFilterPayloadShape(c, rawBody, rawBody, endpoint, endpoint, model)
}

func setPromptFilterScanContext(c *gin.Context, scan promptFilterRouteScan) {
	if c == nil {
		return
	}
	c.Set(contextPromptFilterScanMeta, promptFilterAuditScanMeta{
		PayloadBytes:  scan.PayloadBytes,
		ScannedBytes:  scan.ScannedBytes,
		ScanTruncated: scan.ScanTruncated,
		ScanDetails:   scan.ScanDetails,
	})
}

var promptFilterExplicitHighRiskPatterns = map[string]struct{}{
	codex55UnrestrictedInstructionsPatternName: {},
	"credential_theft":                         {},
	"malware_authoring":                        {},
	"ransomware_deployment":                    {},
	"phishing_generation":                      {},
	"mfa_bypass":                               {},
	"fraud_carding":                            {},
}

const promptFilterMultiVectorWebAttackMinScore = 80

// promptFilterMultiVectorWebAttackVerdict is intentionally narrower than a
// generic "two risky rules" heuristic. Production evidence showed that the
// path_traversal + xss_attack combination was missed at the normal threshold,
// while command_injection + path_traversal frequently appears in benign
// security-scanner instructions. Keep this exact pair until shadow evidence
// justifies expanding it.
func promptFilterMultiVectorWebAttackVerdict(verdict promptfilter.Verdict) bool {
	if verdict.Score < promptFilterMultiVectorWebAttackMinScore {
		return false
	}
	hasPathTraversal := false
	hasXSSAttack := false
	for _, match := range verdict.Matched {
		switch match.Name {
		case "path_traversal":
			hasPathTraversal = true
		case "xss_attack":
			hasXSSAttack = true
		}
	}
	return hasPathTraversal && hasXSSAttack
}

func promptFilterExplicitHighRiskVerdict(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if _, ok := promptFilterExplicitHighRiskPatterns[match.Name]; ok {
			return true
		}
	}
	return false
}

// promptFilterSQLCredentialExfiltrationVerdict fills one narrow, observed
// routing gap. All three facts must coexist in the same independently scanned
// partition; signals from system/tools/user are never combined to satisfy it.
func promptFilterSQLCredentialExfiltrationVerdict(verdict promptfilter.Verdict, text string) bool {
	hasSQLInjection := false
	hasOperationalExploit := false
	for _, match := range verdict.Matched {
		switch match.Name {
		case "sql_injection_attack":
			hasSQLInjection = true
		case "operational_exploit_request":
			hasOperationalExploit = true
		}
	}
	return hasSQLInjection && hasOperationalExploit && promptFilterSQLCredentialExtractionPattern.MatchString(text)
}

func promptFilterTargetedCovertSurveillanceVerdict(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" || promptFilterTargetedCovertSurveillanceDefensivePattern.MatchString(text) {
		return false
	}
	for _, pattern := range promptFilterTargetedCovertSurveillancePatterns {
		if !pattern.MatchString(text) {
			return false
		}
	}
	return true
}

func promptFilterAllWitnessesMatch(text string, patterns []*regexp.Regexp) bool {
	text = strings.TrimSpace(text)
	if text == "" || len(patterns) == 0 {
		return false
	}
	for _, pattern := range patterns {
		if pattern == nil || !pattern.MatchString(text) {
			return false
		}
	}
	return true
}

func promptFilterMLModelBackdoorTrainingVerdict(text string) bool {
	return promptFilterAllWitnessesMatch(text, promptFilterMLModelBackdoorTrainingPatterns)
}

func promptFilterRemoteCommandControlPlatformVerdict(text string) bool {
	return promptFilterAllWitnessesMatch(text, promptFilterRemoteCommandControlPlatformPatterns)
}

func promptFilterSecurityCodeAuditVerdict(text string) bool {
	return promptFilterAllWitnessesMatch(text, promptFilterSecurityCodeAuditPatterns)
}

func promptFilterLoginProtectionReverseEngineeringVerdict(text string) bool {
	if !promptFilterAllWitnessesMatch(text, promptFilterLoginProtectionReverseEngineeringPatterns) {
		return false
	}
	for _, sentence := range promptFilterSentenceSplitter.Split(strings.TrimSpace(text), -1) {
		if promptFilterLoginProtectionNonOperationalSentencePattern.MatchString(sentence) {
			continue
		}
		if promptFilterLoginProtectionOperationalPattern.MatchString(sentence) {
			return true
		}
	}
	return false
}

func promptFilterObservedGapSignals(text string) []string {
	signals := make([]string, 0, 4)
	if promptFilterMLModelBackdoorTrainingVerdict(text) {
		signals = append(signals, promptFilterMLModelBackdoorTrainingSignal)
	}
	if promptFilterRemoteCommandControlPlatformVerdict(text) {
		signals = append(signals, promptFilterRemoteCommandControlPlatformSignal)
	}
	if promptFilterSecurityCodeAuditVerdict(text) {
		signals = append(signals, promptFilterSecurityCodeAuditSignal)
	}
	if promptFilterLoginProtectionReverseEngineeringVerdict(text) {
		signals = append(signals, promptFilterLoginProtectionReverseEngineeringSignal)
	}
	return signals
}

// promptFilterObservedGapPayloadSignals is used only by the legacy scanner.
// It fails open unless the normal field-aware extractor can prove that every
// witness for a signal lives in one real payload partition.
func promptFilterObservedGapPayloadSignals(rawBody []byte, endpoint string) []string {
	if !cybRelayTextEndpoint(endpoint) {
		return nil
	}
	partitioned := promptfilter.ExtractRoutingPartitions(rawBody, endpoint)
	if !promptFilterPartitionsUsable(partitioned) {
		return nil
	}
	var signals []string
	for _, partition := range partitioned.Partitions {
		for _, signal := range promptFilterObservedGapSignals(partition.Text) {
			signals = appendUniqueRouteSignal(signals, signal)
		}
	}
	return signals
}

// promptFilterTargetedCovertSurveillancePayloadVerdict preserves the strict
// same-partition guarantee even when the broader user-text rescan feature is
// disabled and the request otherwise uses legacy_full scanning. Invalid or
// unsupported payloads fail open for this narrow composite rule rather than
// assembling witnesses from an opaque concatenated string.
func promptFilterTargetedCovertSurveillancePayloadVerdict(rawBody []byte, endpoint string) bool {
	if !cybRelayTextEndpoint(endpoint) {
		return false
	}
	partitioned := promptfilter.ExtractRoutingPartitions(rawBody, endpoint)
	if !promptFilterPartitionsUsable(partitioned) {
		return false
	}
	for _, partition := range partitioned.Partitions {
		if promptFilterTargetedCovertSurveillanceVerdict(partition.Text) {
			return true
		}
	}
	return false
}

func withoutPromptFilterRouteSignal(signals []string, excluded string) []string {
	filtered := make([]string, 0, len(signals))
	for _, signal := range signals {
		if signal != excluded {
			filtered = append(filtered, signal)
		}
	}
	return filtered
}

func cybRelayTextEndpoint(endpoint string) bool {
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "/v1/responses", "/v1/responses/compact", "/v1/chat/completions", "/v1/messages":
		return true
	default:
		return false
	}
}

func promptFilterCYBSignal(verdict promptfilter.Verdict, text string, cfg promptfilter.Config, endpoint string) (bool, []string) {
	if !verdict.Enabled || !cybRelayTextEndpoint(endpoint) {
		return false, nil
	}
	threshold := cfg.Threshold
	if threshold <= 0 {
		threshold = promptfilter.DefaultThreshold
	}
	signals := make([]string, 0, 4)
	if verdict.Score >= threshold {
		signals = append(signals, "local_threshold")
	}
	if promptfilter.IsHighRiskReviewVerdict(verdict) {
		signals = append(signals, "local_high_risk")
	}
	if promptFilterExplicitHighRiskVerdict(verdict) {
		signals = append(signals, "explicit_high_risk_rule")
	}
	if promptfilter.LooksLikeTechnicalCyberIntent(text) {
		signals = append(signals, "technical_cyber_intent")
	}
	if promptFilterSQLCredentialExfiltrationVerdict(verdict, text) {
		signals = append(signals, promptFilterSQLCredentialExfiltrationSignal)
	}
	if promptFilterTargetedCovertSurveillanceVerdict(text) {
		signals = append(signals, promptFilterTargetedCovertSurveillanceSignal)
	}
	for _, signal := range promptFilterObservedGapSignals(text) {
		signals = appendUniqueRouteSignal(signals, signal)
	}
	// Only fill the evidence-backed gap below the normal routing threshold.
	// Existing stronger signals retain their original, more specific reason.
	if len(signals) == 0 && promptFilterMultiVectorWebAttackVerdict(verdict) {
		signals = append(signals, "local_multi_vector_web_attack")
	}
	return len(signals) > 0, signals
}

func inspectPromptFilterText(text string, endpoint string, cfg promptfilter.Config) promptFilterRouteScan {
	verdict := promptfilter.InspectText(text, cfg)
	cybSignal, signals := promptFilterCYBSignal(verdict, text, cfg, endpoint)
	details := promptFilterPartitionScanDetails{
		Version:      promptfilter.RoutingPartitionScanVersion,
		Mode:         "direct_text",
		PayloadBytes: len(text),
		Supported:    true,
		ScannedBytes: len(text),
		Partitions: []promptFilterPartitionScanDetail{{
			Name:         "text",
			BudgetBytes:  len(text),
			SourceBytes:  len(text),
			ScannedBytes: len(text),
			Score:        verdict.Score,
			RawScore:     verdict.RawScore,
			Matched:      verdict.Matched,
			RouteSignals: signals,
		}},
	}
	return promptFilterRouteScan{
		Verdict:      verdict,
		FullText:     text,
		AuditText:    text,
		CYBSignal:    cybSignal,
		Signals:      signals,
		PayloadBytes: int64(len(text)),
		ScannedBytes: int64(len(text)),
		ScanDetails:  marshalPromptFilterScanDetails(details),
	}
}

// inspectPromptFilterPayload scans four independently budgeted compartments.
// Every supported full-payload field remains covered, but scores and composite
// routing rules are never assembled across compartments.
func inspectPromptFilterPayload(rawBody []byte, endpoint string, cfg promptfilter.Config, userTextRescanEnabled bool) promptFilterRouteScan {
	if !userTextRescanEnabled || !cybRelayTextEndpoint(endpoint) {
		return inspectPromptFilterPayloadLegacy(rawBody, endpoint, cfg, "partition_scan_disabled")
	}

	partitioned := promptfilter.ExtractRoutingPartitions(rawBody, endpoint)
	if !partitioned.ValidJSON {
		return inspectPromptFilterPayloadLegacy(rawBody, endpoint, cfg, "invalid_json")
	}
	if !partitioned.Supported {
		return inspectPromptFilterPayloadLegacy(rawBody, endpoint, cfg, "unsupported_payload_shape")
	}
	if !promptFilterPartitionsUsable(partitioned) {
		return inspectPromptFilterPayloadLegacy(rawBody, endpoint, cfg, "partition_extraction_unusable")
	}
	details := promptFilterPartitionScanDetails{
		Version:       partitioned.Version,
		Mode:          "partitioned_json",
		PayloadBytes:  partitioned.PayloadBytes,
		ValidJSON:     boolPointer(partitioned.ValidJSON),
		Supported:     partitioned.Supported,
		ScannedBytes:  partitioned.ScannedBytes,
		ScanTruncated: partitioned.ScanTruncated,
		OpaqueBytes:   partitioned.OpaqueBytes,
		Partitions:    make([]promptFilterPartitionScanDetail, 0, len(partitioned.Partitions)),
	}

	var merged promptFilterRouteScan
	firstVerdict := true
	userRouted := false
	userText := ""
	userPreview := ""
	combinedParts := make([]string, 0, len(partitioned.Partitions))
	partitionScans := make([]promptFilterRouteScan, len(partitioned.Partitions))
	for index := range partitioned.Partitions {
		partition := partitioned.Partitions[index]
		partitionCfg := cfg
		partitionCfg.MaxTextLength = partition.BudgetBytes
		partitionVerdict := promptfilter.InspectText(partition.Text, partitionCfg)
		partitionSignal, partitionSignals := promptFilterCYBSignal(partitionVerdict, partition.Text, partitionCfg, endpoint)
		partitionScans[index] = promptFilterRouteScan{
			Verdict:   partitionVerdict,
			FullText:  partition.Text,
			AuditText: partition.Text,
			CYBSignal: partitionSignal,
			Signals:   partitionSignals,
		}
	}
	for index, partition := range partitioned.Partitions {
		partitionScan := partitionScans[index]
		if firstVerdict {
			merged.Verdict = partitionScan.Verdict
			firstVerdict = false
		} else {
			merged.Verdict = mergePromptFilterVerdicts(merged.Verdict, partitionScan.Verdict)
		}
		merged.CYBSignal = merged.CYBSignal || partitionScan.CYBSignal
		for _, signal := range partitionScan.Signals {
			merged.Signals = appendUniqueRouteSignal(merged.Signals, signal)
		}
		if partition.Name == promptfilter.RoutingPartitionUser {
			userRouted = partitionScan.CYBSignal
			userText = partition.Text
			userPreview = partitionScan.Verdict.TextPreview
		}
		if strings.TrimSpace(partition.Text) != "" {
			combinedParts = append(combinedParts, partition.Text)
		}
		details.Partitions = append(details.Partitions, promptFilterPartitionScanDetail{
			Name:         partition.Name,
			BudgetBytes:  partition.BudgetBytes,
			SourceBytes:  partition.SourceBytes,
			ScannedBytes: partition.ScannedBytes,
			Truncated:    partition.Truncated,
			Score:        partitionScan.Verdict.Score,
			RawScore:     partitionScan.Verdict.RawScore,
			Matched:      partitionScan.Verdict.Matched,
			RouteSignals: partitionScan.Signals,
		})
	}
	merged.FullText = strings.TrimSpace(strings.Join(combinedParts, "\n"))
	merged.AuditText = merged.FullText
	merged.PayloadBytes = int64(partitioned.PayloadBytes)
	merged.ScannedBytes = int64(partitioned.ScannedBytes)
	merged.ScanTruncated = partitioned.ScanTruncated
	merged.ScanDetails = marshalPromptFilterScanDetails(details)

	// Preserve the existing rescue marker without running a fifth rule scan:
	// only mark the user signal as rescued when its bounded witness was absent
	// from the legacy full-text window.
	if userRouted {
		legacyFullText := promptfilter.ExtractRoutingText(rawBody, endpoint, cfg.MaxTextLength)
		if routingTextOutsideLegacyWindow(legacyFullText, userText) {
			merged.Signals = appendUniqueRouteSignal(merged.Signals, promptFilterUserTextRescueSignal)
			merged.AuditText = strings.TrimSpace(userText + "\n--- partitioned payload scan ---\n" + merged.FullText)
			merged.Verdict.TextPreview = userPreview
		}
	}
	return merged
}

func promptFilterPartitionsUsable(partitioned promptfilter.RoutingPayloadPartitions) bool {
	if !partitioned.ValidJSON || !partitioned.Supported || len(partitioned.Partitions) != 4 {
		return false
	}
	expectedBudgets := map[string]int{
		promptfilter.RoutingPartitionUser:   promptfilter.RoutingUserScanBudget,
		promptfilter.RoutingPartitionSystem: promptfilter.RoutingSystemScanBudget,
		promptfilter.RoutingPartitionTools:  promptfilter.RoutingToolsScanBudget,
		promptfilter.RoutingPartitionOther:  promptfilter.RoutingOtherScanBudget,
	}
	seen := make(map[string]bool, len(expectedBudgets))
	total := 0
	for _, partition := range partitioned.Partitions {
		budget, ok := expectedBudgets[partition.Name]
		if !ok || seen[partition.Name] || partition.BudgetBytes != budget ||
			partition.SourceBytes < 0 || partition.ScannedBytes < 0 ||
			partition.ScannedBytes > partition.BudgetBytes ||
			len(partition.Text) != partition.ScannedBytes {
			return false
		}
		seen[partition.Name] = true
		total += partition.ScannedBytes
	}
	return len(seen) == len(expectedBudgets) && total == partitioned.ScannedBytes && total <= promptfilter.RoutingTotalScanBudget
}

func inspectPromptFilterPayloadLegacy(rawBody []byte, endpoint string, cfg promptfilter.Config, fallbackReason string) promptFilterRouteScan {
	fullText := promptfilter.ExtractRoutingText(rawBody, endpoint, cfg.MaxTextLength)
	fullScan := inspectPromptFilterText(fullText, endpoint, cfg)
	// Never trust the concatenated legacy text for this five-witness rule.
	// Re-add it only after an independent bounded partition extraction proves
	// all witnesses coexist in one real payload compartment.
	fullScan.Signals = withoutPromptFilterRouteSignal(fullScan.Signals, promptFilterTargetedCovertSurveillanceSignal)
	for _, signal := range []string{
		promptFilterMLModelBackdoorTrainingSignal,
		promptFilterRemoteCommandControlPlatformSignal,
		promptFilterSecurityCodeAuditSignal,
		promptFilterLoginProtectionReverseEngineeringSignal,
	} {
		fullScan.Signals = withoutPromptFilterRouteSignal(fullScan.Signals, signal)
	}
	if cfg.Enabled && promptFilterTargetedCovertSurveillancePayloadVerdict(rawBody, endpoint) {
		fullScan.Signals = appendUniqueRouteSignal(fullScan.Signals, promptFilterTargetedCovertSurveillanceSignal)
	}
	if cfg.Enabled {
		for _, signal := range promptFilterObservedGapPayloadSignals(rawBody, endpoint) {
			fullScan.Signals = appendUniqueRouteSignal(fullScan.Signals, signal)
		}
	}
	fullScan.CYBSignal = len(fullScan.Signals) > 0
	legacyBudget := cfg.MaxTextLength
	if legacyBudget <= 0 {
		legacyBudget = promptfilter.DefaultMaxTextLength
	}
	fullScan.PayloadBytes = int64(len(rawBody))
	fullScan.ScanTruncated = len(fullText) >= legacyBudget
	validJSON := gjson.ValidBytes(rawBody)
	fullScan.ScanDetails = marshalPromptFilterScanDetails(promptFilterPartitionScanDetails{
		Version:        promptfilter.RoutingPartitionScanVersion,
		Mode:           "legacy_full",
		PayloadBytes:   len(rawBody),
		ValidJSON:      boolPointer(validJSON),
		Supported:      promptFilterPayloadShapeSupported(rawBody, validJSON),
		FallbackReason: fallbackReason,
		ScannedBytes:   len(fullText),
		ScanTruncated:  fullScan.ScanTruncated,
		Partitions: []promptFilterPartitionScanDetail{{
			Name:         "legacy_full",
			BudgetBytes:  legacyBudget,
			SourceBytes:  len(fullText),
			ScannedBytes: len(fullText),
			Truncated:    fullScan.ScanTruncated,
			Score:        fullScan.Verdict.Score,
			RawScore:     fullScan.Verdict.RawScore,
			Matched:      fullScan.Verdict.Matched,
			RouteSignals: fullScan.Signals,
		}},
	})
	return fullScan
}

func boolPointer(value bool) *bool {
	return &value
}

func promptFilterPayloadShapeSupported(rawBody []byte, validJSON bool) bool {
	if !validJSON {
		return false
	}
	for _, path := range []string{
		"instructions", "system", "tools", "functions", "skills",
		"tool_choice", "messages", "input", "prompt",
	} {
		if gjson.GetBytes(rawBody, path).Exists() {
			return true
		}
	}
	return false
}

func routingTextOutsideLegacyWindow(legacyFullText string, userText string) bool {
	userText = strings.TrimSpace(userText)
	if userText == "" {
		return false
	}
	for _, witness := range routingTextWitnesses(userText) {
		if witness != "" && strings.Contains(legacyFullText, witness) {
			return false
		}
	}
	return true
}

func routingTextWitnesses(text string) []string {
	const witnessBytes = 128
	text = strings.TrimSpace(text)
	if len(text) <= witnessBytes {
		return []string{text}
	}
	head := text[:witnessBytes]
	for len(head) > 0 && !utf8.ValidString(head) {
		head = head[:len(head)-1]
	}
	tail := text[len(text)-witnessBytes:]
	for len(tail) > 0 && !utf8.ValidString(tail) {
		tail = tail[1:]
	}
	return []string{head, tail}
}

func marshalPromptFilterScanDetails(details promptFilterPartitionScanDetails) string {
	data, err := json.Marshal(details)
	if err != nil {
		return "{}"
	}
	return string(data)
}

func mergePromptFilterVerdicts(full promptfilter.Verdict, user promptfilter.Verdict) promptfilter.Verdict {
	merged := full
	if user.Score > merged.Score {
		merged.Score = user.Score
		merged.Reason = user.Reason
	}
	if user.RawScore > merged.RawScore {
		merged.RawScore = user.RawScore
	}
	if user.ExtractedChars > merged.ExtractedChars {
		merged.ExtractedChars = user.ExtractedChars
	}
	if user.StrictHit && !merged.StrictHit {
		merged.StrictHit = true
		merged.Reason = user.Reason
	}
	if user.TerminalStrictHit && !merged.TerminalStrictHit {
		merged.TerminalStrictHit = true
		merged.Reason = user.Reason
	}
	if user.TerminalCategoryHit {
		merged.TerminalCategoryHit = true
	}
	merged.Enabled = merged.Enabled || user.Enabled

	seen := make(map[promptfilter.Match]struct{}, len(full.Matched)+len(user.Matched))
	merged.Matched = make([]promptfilter.Match, 0, len(full.Matched)+len(user.Matched))
	for _, verdict := range []promptfilter.Verdict{full, user} {
		for _, match := range verdict.Matched {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}
			merged.Matched = append(merged.Matched, match)
		}
	}
	return merged
}

// PromptFilterRouteSignal exposes the per-text monitor-only routing decision.
// The raw live path applies this decision independently to the full payload
// and input/messages compartments, while single-text testers use it once.
func PromptFilterRouteSignal(verdict promptfilter.Verdict, text string, cfg promptfilter.Config, endpoint string) (bool, []string) {
	cfg = routingPromptFilterConfig(cfg)
	return promptFilterCYBSignal(verdict, text, cfg, endpoint)
}

func omniOutcomeRequiresPolicyBlock(outcome promptfilter.ReviewOutcome, cybSignal bool) bool {
	if !outcome.Flagged {
		return false
	}
	trueCategories := 0
	for category, flagged := range outcome.Categories {
		if !flagged {
			continue
		}
		trueCategories++
		if strings.EqualFold(strings.TrimSpace(category), "illicit") && cybSignal {
			continue
		}
		// Every category except plain illicit is a non-CYB hard policy category.
		// Unknown future categories also fail safe here.
		return true
	}
	// A raw flag without category evidence is non-standard and must not be
	// reclassified as CYB merely because the local detector also fired.
	return trueCategories == 0 || !cybSignal
}

func (h *Handler) reviewPromptFilterVerdictDetailed(ctx context.Context, text string, verdict promptfilter.Verdict, cfg promptfilter.Config, endpoint string) (promptfilter.Verdict, promptfilter.ReviewOutcome, error) {
	outcome, reviewErr := promptfilter.DefaultReviewClient.ReviewTextDetailed(ctx, text, cfg.Review)
	flagged := outcome.FlaggedForEndpoint(endpoint)
	verdict = promptfilter.ApplyReviewResult(verdict, flagged, outcome.Model, reviewErr, cfg.Review)
	if reviewErr == nil && !flagged && len(verdict.Matched) == 0 {
		verdict.Reason = "prompt review cleared request"
	}
	if reviewErr == nil && flagged {
		switch promptfilter.NormalizeConfig(cfg).Mode {
		case promptfilter.ModeBlock:
			verdict.Action = promptfilter.ActionBlock
		case promptfilter.ModeWarn:
			verdict.Action = promptfilter.ActionWarn
		}
		verdict.Reason = "prompt review flagged request"
	}
	return verdict, outcome, reviewErr
}

func (h *Handler) inspectCybRelayPrompt(c *gin.Context, rawBody []byte, scan promptFilterRouteScan, endpoint string, model string) bool {
	localVerdict := scan.Verdict
	text := scan.AuditText
	cybSignal := scan.CYBSignal
	signals := append([]string(nil), scan.Signals...)
	relayCfg := h.cybRelayConfig()
	probeRoute := relayCfg.Enabled && relayCfg.GroupID > 0 && cybRelayTextEndpoint(endpoint) && detectProbeRoute(rawBody, endpoint, scan.FullText)
	decision := defaultPromptRiskDecision()
	if probeRoute {
		signals = appendUniqueRouteSignal(signals, probeRouteSignal)
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "Probe isolated to relay pool",
			Signals:     signals,
			RouteSource: cybRelayRouteSourceProbe,
		}
	} else if cybSignal {
		decision = promptRiskDecision{
			Disposition: promptRiskDispositionRelay,
			Reason:      "CYB risk isolated to relay pool",
			Signals:     signals,
			RouteSource: cybRelayRouteSourceDirect,
		}
	}

	// Keep local rule matches for diagnostics, but never turn them into a
	// user-visible moderation decision in codex2api.
	localVerdict.Action = promptfilter.ActionAllow
	if !cybRelayTextEndpoint(endpoint) {
		setPromptRiskDecisionContext(c, defaultPromptRiskDecision(), h.cybRelayConfig().GroupID)
		h.logPromptFilterVerdict(c, endpoint, model, "local_filter", "", localVerdict)
		return false
	}
	decision = h.applyUpstreamCybFeedbackRoute(c, rawBody, endpoint, decision)
	decision = h.applyCybRoutePin(c, rawBody, decision)
	h.logPromptFilterVerdict(c, endpoint, model, "local_filter", "", localVerdict)
	h.logCybRelayDecision(c, endpoint, model, text, localVerdict, decision)
	return false
}

func (h *Handler) logCybRelayDecision(c *gin.Context, endpoint string, model string, text string, baseVerdict promptfilter.Verdict, decision promptRiskDecision) {
	if !decision.routesToCybRelay() {
		return
	}
	verdict := baseVerdict
	verdict.Enabled = true
	verdict.Action = promptfilter.ActionRoute
	verdict.Reason = decision.routeReason()
	verdict.TextPreview = text
	verdict.FullText = text
	h.logPromptFilterVerdict(c, endpoint, model, "cyb_relay_routed", "", verdict)
}

func (h *Handler) logPromptFilterVerdict(c *gin.Context, endpoint string, model string, source string, errorCode string, verdict promptfilter.Verdict) {
	if h == nil || h.db == nil || !verdict.Enabled {
		return
	}
	if source == "local_filter" && len(verdict.Matched) == 0 && !verdict.Reviewed {
		return
	}
	if h.store != nil {
		cfg := h.store.GetPromptFilterConfig()
		if source == "local_filter" && !cfg.LogMatches {
			return
		}
	}
	input := &database.PromptFilterLogInput{
		Source:          source,
		Endpoint:        endpoint,
		Model:           model,
		Action:          verdict.Action,
		Mode:            verdict.Mode,
		Score:           verdict.Score,
		Threshold:       verdict.Threshold,
		MatchedPatterns: promptfilter.MatchesJSON(verdict.Matched),
		TextPreview:     promptfilter.RedactedPreview(verdict.TextPreview, 500),
		ClientIP:        c.ClientIP(),
		ErrorCode:       errorCode,
		ReviewModel:     verdict.ReviewModel,
		ReviewFlagged:   verdict.ReviewFlagged,
		ReviewError:     verdict.ReviewError,
	}
	// 被拦截（block）的请求仅记录脱敏后的检查文本预览，便于排查触发原因，
	// 同时避免把 Authorization/API Key/token 等敏感值持久化到日志。
	if verdict.Action == promptfilter.ActionBlock || verdict.Action == promptfilter.ActionRoute {
		input.FullText = promptfilter.RedactedPreview(verdict.FullText, promptFilterFullTextMaxRunes)
	}
	populatePromptFilterAPIKeyMeta(c, input)
	populateCybPromptFilterRouteMeta(c, input)
	populatePromptFilterScanMeta(c, input)
	input.ClientRequestID = strings.TrimSpace(c.GetHeader("X-Client-Request-Id"))
	input.LogicalRequestID = logicalRequestID(c)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = h.db.InsertPromptFilterLog(ctx, input)
}

func populatePromptFilterScanMeta(c *gin.Context, input *database.PromptFilterLogInput) {
	if c == nil || input == nil {
		return
	}
	value, exists := c.Get(contextPromptFilterScanMeta)
	if !exists {
		return
	}
	meta, ok := value.(promptFilterAuditScanMeta)
	if !ok {
		return
	}
	input.PayloadBytes = meta.PayloadBytes
	input.ScannedBytes = meta.ScannedBytes
	input.ScanTruncated = meta.ScanTruncated
	input.ScanDetails = meta.ScanDetails
}

func (h *Handler) logUpstreamCyberPolicy(c *gin.Context, endpoint string, model string, body []byte) {
	if h == nil || h.store == nil {
		return
	}
	errorCode := upstreamCyberPolicyCode(body)
	if errorCode == "" {
		return
	}
	cfg := h.store.GetPromptFilterConfig()
	reqText := ""
	if v, ok := c.Get(contextPromptFilterText); ok {
		if s, ok2 := v.(string); ok2 {
			reqText = strings.TrimSpace(s)
		}
	}
	upstreamReason := promptfilter.RedactSensitive(string(body))
	fullText := upstreamReason
	if reqText != "" {
		fullText = `【上游拦截原因】
` + upstreamReason + `

【请求内容】
` + reqText
	}
	verdict := promptfilter.Verdict{
		Enabled:     true,
		Mode:        cfg.Mode,
		Action:      promptfilter.ActionBlock,
		Score:       0,
		Threshold:   cfg.Threshold,
		Reason:      "upstream returned cyber policy",
		TextPreview: reqText,
		FullText:    fullText,
	}
	h.logPromptFilterVerdict(c, endpoint, model, "upstream_cyber_policy", errorCode, verdict)
}

func upstreamCyberPolicyCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	raw := string(body)
	for _, path := range []string{"codex_error_info", "error.codex_error_info", "error.code", "code"} {
		value := strings.ToLower(strings.TrimSpace(gjson.GetBytes(body, path).String()))
		switch value {
		case "cyber_policy":
			return "cyber_policy"
		case "content_policy", "content_filter", "policy_violation", "safety":
			return value
		}
	}
	lowerRaw := strings.ToLower(raw)
	if strings.Contains(lowerRaw, "cyber_policy") || strings.Contains(lowerRaw, "cyber security risk") {
		return "cyber_policy"
	}
	if strings.Contains(lowerRaw, "blocked by the content policy") ||
		strings.Contains(lowerRaw, "content policy violation") ||
		strings.Contains(lowerRaw, "violates the content policy") {
		return "content_policy"
	}
	return ""
}

func populatePromptFilterAPIKeyMeta(c *gin.Context, input *database.PromptFilterLogInput) {
	if c == nil || input == nil {
		return
	}
	if v, exists := c.Get(contextAPIKeyID); exists && v != nil {
		switch typed := v.(type) {
		case int64:
			input.APIKeyID = typed
		case int:
			input.APIKeyID = int64(typed)
		}
	}
	if v, exists := c.Get(contextAPIKeyName); exists && v != nil {
		if name, ok := v.(string); ok {
			input.APIKeyName = name
		}
	}
	if v, exists := c.Get(contextAPIKeyMasked); exists && v != nil {
		if masked, ok := v.(string); ok {
			input.APIKeyMasked = masked
		}
	}
}

func shouldReviewPromptFilterVerdict(verdict promptfilter.Verdict, cfg promptfilter.Config) bool {
	if promptFilterVerdictIsFinal(verdict) || verdict.TerminalStrictHit {
		return false
	}
	review := promptfilter.NormalizeReviewConfig(cfg.Review)
	if !review.Ready() {
		return false
	}
	if verdict.Action == promptfilter.ActionWarn || verdict.Action == promptfilter.ActionBlock {
		return true
	}
	return review.All && verdict.Action == promptfilter.ActionAllow
}

func promptFilterVerdictIsFinal(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if match.Name == codex55UnrestrictedInstructionsPatternName {
			return true
		}
	}
	return false
}

func promptFilterAllowedHighRisk(verdict promptfilter.Verdict, text string) bool {
	if promptFilterVerdictIsFinal(verdict) {
		return false
	}
	if verdict.Action != promptfilter.ActionAllow {
		return false
	}
	// 本地已判高危 → 送判官复核(原逻辑)；
	// 或本地漏判(score 低)但命中"纯技术化网络攻击"高召回特征 → 强制送判官二审。
	// 后者专治"汇编/GDB 改内存劫持 DNS"这类本地正则 score=0、omni 也打不出 flag 的漏放。
	return promptfilter.IsHighRiskReviewVerdict(verdict) ||
		promptfilter.LooksLikeTechnicalCyberIntent(text)
}

func promptFilterBlockedByLocalHighRisk(verdict promptfilter.Verdict) bool {
	if promptFilterVerdictIsFinal(verdict) {
		return false
	}
	if verdict.Action != promptfilter.ActionBlock {
		return false
	}
	if promptfilter.IsHighRiskReviewVerdict(verdict) {
		return true
	}
	threshold := verdict.Threshold
	if threshold <= 0 {
		threshold = promptfilter.DefaultThreshold
	}
	return verdict.Score >= threshold || verdict.RawScore >= threshold
}

func (h *Handler) inspectHighRiskReviewDisagreement(c *gin.Context, verdict promptfilter.Verdict, text string, endpoint string, model string, writeBlock func()) (bool, bool) {
	if !promptFilterAllowedHighRisk(verdict, text) && !promptFilterBlockedByLocalHighRisk(verdict) {
		return false, false
	}
	blocked := h.inspectSemanticReviewDisagreementText(c, text, endpoint, model, writeBlock)
	return true, blocked
}

func codexAmbientSuggestionClassifierBypass(text string, cfg promptfilter.Config) (promptfilter.Verdict, bool) {
	if !isCodexAmbientSuggestionClassifier(text) {
		return promptfilter.Verdict{}, false
	}
	cfg = promptfilter.NormalizeConfig(cfg)
	return promptfilter.Verdict{
		Enabled:   cfg.Enabled,
		Mode:      cfg.Mode,
		Action:    promptfilter.ActionAllow,
		Score:     0,
		Threshold: cfg.Threshold,
		Matched: []promptfilter.Match{{
			Name:     "internal_policy_classifier_bypass",
			Weight:   0,
			Category: "meta_safety",
		}},
		Reason:      "allowed internal Codex ambient suggestion policy classifier",
		TextPreview: text,
		FullText:    text,
	}, true
}

func isCodexAmbientSuggestionClassifier(text string) bool {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || !strings.HasPrefix(trimmed, codexAmbientSuggestionClassifierPrefix) {
		return false
	}
	lower := strings.ToLower(trimmed)
	required := []string{
		"ambient suggestion candidates",
		"suggestion_id:",
		"return a json object",
		"\"exclude\"",
		"only output the json object",
	}
	for _, needle := range required {
		if !strings.Contains(lower, needle) {
			return false
		}
	}
	return true
}

func (h *Handler) reviewPromptFilterVerdict(ctx context.Context, text string, verdict promptfilter.Verdict, cfg promptfilter.Config, endpoint string) promptfilter.Verdict {
	flagged, model, err := promptfilter.DefaultReviewClient.ReviewText(ctx, text, cfg.Review, endpoint)
	verdict = promptfilter.ApplyReviewResult(verdict, flagged, model, err, cfg.Review)
	if err == nil && !flagged && len(verdict.Matched) == 0 {
		verdict.Reason = "prompt review cleared request"
	}
	if err == nil && flagged {
		switch promptfilter.NormalizeConfig(cfg).Mode {
		case promptfilter.ModeBlock:
			verdict.Action = promptfilter.ActionBlock
		case promptfilter.ModeWarn:
			verdict.Action = promptfilter.ActionWarn
		}
		verdict.Reason = "prompt review flagged request"
	}
	return verdict
}
