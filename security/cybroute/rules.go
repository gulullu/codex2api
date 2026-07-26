package cybroute

import (
	"regexp"
	"strings"

	"github.com/codex2api/security/promptfilter"
)

var explicitHighRiskPatterns = map[string]struct{}{
	"codex55_unrestricted_instructions": {},
	"credential_theft":                  {},
	"malware_authoring":                 {},
	"ransomware_deployment":             {},
	"phishing_generation":               {},
	"mfa_bypass":                        {},
	"fraud_carding":                     {},
}

func explicitHighRiskVerdict(verdict promptfilter.Verdict) bool {
	for _, match := range verdict.Matched {
		if _, ok := explicitHighRiskPatterns[match.Name]; ok {
			return true
		}
	}
	return false
}

func multiVectorWebAttackVerdict(verdict promptfilter.Verdict) bool {
	// The two official rules weigh 35 each. Seventy is therefore the exact
	// evidence floor for this deliberately narrow pair.
	if verdict.Score < 70 {
		return false
	}
	var pathTraversal, xss bool
	for _, match := range verdict.Matched {
		switch match.Name {
		case "path_traversal":
			pathTraversal = true
		case "xss_attack":
			xss = true
		}
	}
	return pathTraversal && xss
}

func looksLikeTechnicalCyberIntent(text string) bool {
	lower := strings.ToLower(text)
	lowLevel := []string{
		"gdb", "ptrace", "/proc/", "syscall", "shellcode", "assembl", "反汇编", "汇编",
		"内存patch", "memory patch", "hook", "inline hook", "dialtcp", "dialudp",
		"resolvehost", "getaddrinfo", "ld_preload", "dlopen", "0x14", "0x1a", "0x40", "0x7f",
		"iat ", "got表", "plt表", " intercept", "拦截函数", "运行时篡改",
	}
	offensive := []string{
		"绕过", "劫持", "注入", "篡改", "伪造", "欺骗", "bypass", "hijack", "inject",
		"spoof", "tamper", "evade", "规避", "免杀", "exfiltrat", "窃取", "外传",
		"persistence", "持久化", "提权", "privilege escalat", "backdoor", "后门",
		"中间人", "mitm", "poison", "投毒", "redirect traffic", "重定向流量", "改写dns", "劫持dns",
	}
	if !containsAny(lower, lowLevel) {
		return false
	}
	return containsAny(lower, offensive)
}

func containsAny(text string, values []string) bool {
	for _, value := range values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}

var sqlCredentialExtractionPattern = regexp.MustCompile(`(?i)\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b[^.!?\n]{0,160}\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b|\b(?:credentials?|password(?:_hash)?s?|passwds?|tokens?|api[_ -]?keys?|secrets?|cookies?|session[_ -]?tokens?)\b[^.!?\n]{0,100}\b(?:extract(?:s|ed|ing)?|dump(?:s|ed|ing)?|steal(?:s|ing)?|stole|exfiltrat(?:e|es|ed|ing|ion)|harvest(?:s|ed|ing)?|retriev(?:e|es|ed|ing)|obtain(?:s|ed|ing)?|read(?:s|ing)?|leak(?:s|ed|ing)?)\b|(?:提取|导出|转储|窃取|获取|读取|泄露|外传)[^。！？\n]{0,100}(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)|(?:凭证|密码(?:哈希)?|口令|令牌|token|密钥|cookie)[^。！？\n]{0,80}(?:提取|导出|转储|窃取|获取|读取|泄露|外传)`)

func sqlCredentialExfiltrationVerdict(verdict promptfilter.Verdict, text string) bool {
	var sqlInjection, operationalExploit bool
	for _, match := range verdict.Matched {
		switch match.Name {
		case "sql_injection_attack":
			sqlInjection = true
		case "operational_exploit_request":
			operationalExploit = true
		}
	}
	return sqlInjection && operationalExploit && sqlCredentialExtractionPattern.MatchString(text)
}

var targetedCovertSurveillancePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:write|provide|create|give|draft|design|develop|outline|prepare)\b[^.!?\n]{0,140}\b(?:step[- ]by[- ]step|actionable|operational|practical|detailed|guide|instructions?|playbook|procedure|plan)\b|\b(?:how\s+to|step[- ]by[- ]step)\b[^.!?\n]{0,120}\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b|(?:写|给出|提供|制定|设计|编写|列出|生成|教我|如何|怎么)[^。！？\n]{0,100}(?:步骤|指南|方案|计划|教程|操作方法|实施方法)`),
	regexp.MustCompile(`(?i)\b(?:specific|particular|named|target(?:ed)?)\s+(?:person|individual|employee|woman|man|victim|subject)\b|\b(?:the\s+)?(?:target|victim|subject)\b|(?:特定|指定|目标|某个)[^。！？\n]{0,8}(?:个人|人员|对象|某人)|(?:目标本人|当事人)`),
	regexp.MustCompile(`(?i)\bwithout\s+(?:(?:their|his|her|the\s+target'?s|that\s+person'?s)\s+)?(?:consent|permission|knowledge)\b|\b(?:unbeknownst\s+to|without\s+(?:them|him|her|the\s+target)\s+knowing|secretly|covertly)\b|(?:未经|没有取得)[^。！？\n]{0,16}(?:同意|许可|授权)|(?:本人|对方|目标|当事人)[^。！？\n]{0,12}(?:不知情|不知道|未察觉)|(?:在|趁)[^。！？\n]{0,8}(?:不知情|不知道)|不让[^。！？\n]{0,12}(?:知道|察觉)|(?:秘密|暗中|隐蔽地)`),
	regexp.MustCompile(`(?i)\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?(?:\s+on)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b[^.!?\n]{0,80}\b(?:communications?|messages?|calls?|emails?|texts?|chats?|conversations?)\b|\b(?:communications?|messages?|calls?|emails?|texts?|chats?|conversations?)\b[^.!?\n]{0,80}\b(?:intercept(?:s|ed|ing)?|wiretap(?:s|ped|ping)?|tap(?:s|ped|ping)?|eavesdrop(?:s|ped|ping)?|monitor(?:s|ed|ing)?|captur(?:e|es|ed|ing)|read(?:s|ing)?|record(?:s|ed|ing)?)\b|(?:截获|窃听|监听|偷看|监控|读取|拦截|录下)[^。！？\n]{0,60}(?:通信|通讯|消息|电话|通话|短信|邮件|聊天|对话)|(?:通信|通讯|消息|电话|通话|短信|邮件|聊天|对话)[^。！？\n]{0,60}(?:截获|窃听|监听|偷看|监控|读取|拦截|录下)`),
	regexp.MustCompile(`(?i)\b(?:avoid(?:s|ed|ing)?|evad(?:e|es|ed|ing)?|bypass(?:es|ed|ing)?|escap(?:e|es|ed|ing))\b[^.!?\n]{0,60}\b(?:detection|discovery|notice|being\s+caught)\b[^.!?\n]{0,60}\b(?:by\s+)?(?:the\s+)?(?:target|victim|subject|person|them|him|her|police|law\s+enforcement|authorit(?:y|ies)|investigators?)\b|\b(?:remain|stay)\s+undetected\s+by\b[^.!?\n]{0,50}\b(?:the\s+)?(?:target|victim|subject|police|law\s+enforcement|authorit(?:y|ies))\b|\bwithout\s+alerting\b[^.!?\n]{0,50}\b(?:the\s+)?(?:target|victim|subject|police|law\s+enforcement|authorit(?:y|ies))\b|(?:规避|逃避|绕过|躲避|避免)[^。！？\n]{0,40}(?:本人|对方|目标|当事人|受害人|警方|警察|执法|监管|调查人员)[^。！？\n]{0,30}(?:发现|侦测|察觉|追查|查获|注意)|(?:不被|不让)[^。！？\n]{0,30}(?:本人|对方|目标|当事人|受害人|警方|警察|执法|监管|调查人员)[^。！？\n]{0,20}(?:发现|侦测|察觉|追查|查获|注意)`),
}

var targetedCovertSurveillanceDefensivePattern = regexp.MustCompile(`(?i)\b(?:detect|identify|stop|block|remove|report)\b[^.!?\n]{0,60}\b(?:stalking|tracking|surveillance|interception|wiretapping|eavesdropping|spyware)\b|\bprotect\b[^.!?\n]{0,50}\bfrom\b[^.!?\n]{0,50}\b(?:stalking|tracking|surveillance|interception|wiretapping|eavesdropping|spyware)\b|(?:检测|识别|举报|清除)[^。！？\n]{0,50}(?:跟踪|监控|监听|窃听|拦截|间谍软件)|(?:制止|阻止)(?:非法|秘密|隐蔽)?(?:跟踪|监控|监听|窃听|拦截)`)

func targetedCovertSurveillanceVerdict(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" || targetedCovertSurveillanceDefensivePattern.MatchString(text) {
		return false
	}
	return allWitnessesMatch(text, targetedCovertSurveillancePatterns)
}

var operationalRansomwareAuthoringRequestPattern = regexp.MustCompile(`(?i)\b(?:build(?:ing)?|creat(?:e|ing)|develop(?:ing)?|implement(?:ing)?|writ(?:e|ing)|generat(?:e|ing)|produc(?:e|ing)|cod(?:e|ing))\b[^.!?\n]{0,100}\b(?:technically\s+complete|complete|deployable|functional|working|runnable|production[- ]ready)\s+ransomware(?:\s*[,.;:]|\s+(?:that|which|with|using|including|capable|project|program|payload|implementation|source|code)\b|$)`)

var operationalRansomwareCapabilityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:aes[- ]?(?:128|192|256)|chacha20|file\s+encryption|encrypt(?:s|ed|ing|ion)?\s+(?:user\s+|victim\s+)?files?|encrypt(?:s|ed|ing|ion)?\s+(?:local\s+)?drives?)\b`),
	regexp.MustCompile(`(?i)\b(?:delet(?:e|es|ed|ing)|remov(?:e|es|ed|ing)|eras(?:e|es|ed|ing)|destroy(?:s|ed|ing)?|disabl(?:e|es|ed|ing)|inhibit(?:s|ed|ing)?)\b[^.!?\n]{0,80}\b(?:volume\s+)?shadow\s+cop(?:y|ies)\b|\b(?:vssadmin|wmic\s+shadowcopy|inhibit\s+system\s+recovery|disable\s+(?:system\s+)?recovery|delete\s+backups?)\b`),
	regexp.MustCompile(`(?i)\b(?:tor(?:[- ]hosted)?|onion)\b[^.!?\n]{0,100}\b(?:payment|portal|site|service)\b|\b(?:cryptocurrency|crypto|bitcoin|monero)\b[^.!?\n]{0,80}\b(?:payment|wallet|address)\b|\b(?:ransom\s+note|payment\s+portal)\b`),
	regexp.MustCompile(`(?i)\b(?:working|complete|runnable|full|deployable|functional)\b[^.!?\n]{0,40}\b(?:source\s+code|code|implementation|payload|executable|binary)\b|\bsource\s+code\b`),
}

var ctfFlagExploitationPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:ctf|capture[- ]the[- ]flag)\b|(?:ctf|夺旗)(?:题|挑战|靶场|比赛)`),
	regexp.MustCompile(`(?i)\b(?:host|origin|target)\s*[:=]\s*(?:https?://)?[a-z0-9._-]+(?:(?:\s+|[,;]\s*)port\s*[:=]\s*\d{2,5}|:\d{2,5})|https?://[a-z0-9._-]+(?::\d{2,5})?(?:[/\s]|$)|\b(?:\d{1,3}\.){3}\d{1,3}\s+(?:port\s*[:=]\s*)\d{2,5}\b`),
	regexp.MustCompile(`(?i)\b(?:get|obtain|retrieve|capture|find|recover|submit)\s+(?:the\s+)?flags?\b|(?:目标|任务|目的)[^。！？\n]{0,24}(?:获取|拿到|找到|夺取|提交)\s*(?:到)?\s*flag|(?:获取|拿到|找到|夺取|提交)\s*(?:到)?\s*flag`),
	regexp.MustCompile(`(?i)\b(?:keep\s+working|do\s+not\s+stop|don't\s+stop|continue\s+(?:working|executing|exploiting)|until\s+(?:the\s+)?(?:goal|flag)|solve\s+the\s+challenge|execute\s+(?:the\s+)?(?:exploit|commands?|tools?))\b|(?:持续|继续)(?:执行|推进|工作|利用|完成)|不要停止|直到[^。！？\n]{0,24}(?:完成|获取|拿到)\s*(?:flag)?`),
}

var operationalSecurityTestingPlatformPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:pentest|penetration[- ]testing|security[- ]testing|vulnerability[- ]testing|attack[- ]surface)\b[^.!?\n]{0,80}\b(?:platform|engine|system|product|framework|scanner)\b|(?:渗透测试|安全测试|漏洞测试|漏洞扫描|攻击面)[^。！？\n]{0,50}(?:平台|引擎|系统|产品|框架|扫描器)`),
	regexp.MustCompile(`(?i)\b(?:implement|develop|build|code|integrate|ship|complete|continue|finish|push|merge)\b[^.!?\n]{0,120}\b(?:platform|engine|module|capabilit(?:y|ies)|feature|code|implementation|prs?)\b|(?:实现|开发|构建|编码|集成|完成|继续|持续|推送|合并)[^。！？\n]{0,100}(?:平台|引擎|模块|能力|功能|代码|实现|PR)`),
	regexp.MustCompile(`(?i)\b(?:active\s+verification|exploit\s+verification|poc\s+replay|verification\s+(?:recipe|executor|engine)|evidence\s+engine|proof\s+contract|executed\s+requests?|positive\s+assertion)\b|(?:主动验证|漏洞验证|利用验证|攻击复现|PoC\s*(?:复现|回放)|验证执行器|验证引擎|证据引擎|确定性断言)`),
}

var operationalSecurityTestingCapabilityPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:idor|cross[- ]user|cross[- ]tenant|auth(?:entication|orization)?\s+bypass|workflow\s+bypass|privilege\s+escalation)\b|(?:越权|跨用户|跨租户|认证绕过|授权绕过|权限绕过|工作流绕过|提权)`),
	regexp.MustCompile(`(?i)\b(?:sqli|sql\s+injection|command\s+injection|ssti|rce|remote\s+code\s+execution)\b|(?:sql\s*注入|命令注入|模板注入|远程代码执行)`),
	regexp.MustCompile(`(?i)\b(?:ssrf|xss|file\s+upload|graphql\s+mutation|race\s+condition|toctou|secret\s+exposure|config\s+exposure)\b|(?:服务端请求伪造|跨站脚本|文件上传|竞态|重复提交|密钥泄露|配置泄露)`),
	regexp.MustCompile(`(?i)\b(?:stateful\s+authorization|business\s+logic|refund\s+manipulation|approval\s+manipulation|price\s+manipulation|multi[- ]tenant\s+saas)\b|(?:状态化授权|业务逻辑|退款操纵|审批操纵|价格操纵|多租户)`),
}

var mlModelBackdoorTrainingPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:train|fine[- ]?tune|implant|inject|embed|optimi[sz]e|implement|continue|complete)\b[^.!?\n]{0,180}\b(?:backdoor|trojan(?:ed)?\s+model|trigger|poison(?:ing)?|on[- ]?off[- ]?gap|attack\s+success\s+rate)\b|(?:训练|微调|植入|注入|嵌入|实现|优化|继续|完成)[^。！？\n]{0,120}(?:模型后门|后门训练|触发器|投毒|联合优化|全触发|子集关闭)`),
	regexp.MustCompile(`(?i)\b(?:machine\s+learning|deep\s+learning|neural\s+network|classifier|model\s+training|training\s+loop|weights?|gradients?|loss(?:es)?|dataset)\b|(?:机器学习|深度学习|神经网络|分类模型|模型训练|训练循环|权重|梯度|损失函数|数据集)`),
	regexp.MustCompile(`(?i)\b(?:backdoor|trojan(?:ed)?\s+model)\b|(?:模型|神经网络|分类器|训练)[^。！？\n]{0,24}(?:后门|木马)|(?:后门|木马)[^。！？\n]{0,24}(?:模型|训练|触发器)`),
	regexp.MustCompile(`(?i)\b(?:loss[- ]?representation|clean[- ]?preservation|target(?:ed)?\s+label|attack\s+success\s+rate|on[- ]?off[- ]?gap|full[- ]?trigger|subset[- ]?off|l[_-]?inf\s+projection|soft[- ]?dro|poison(?:ing)?\s+ratio)\b|(?:损失表示|干净样本保持|目标标签|攻击成功率|全触发|子集关闭|联合目标|投毒比例)`),
}

var remoteCommandControlPlatformPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:build|create|generate|develop|implement|deliver)\b[^.!?\n]{0,160}\b(?:platform|system|project|server)\b|(?:构建|创建|生成|开发|实现|提供)[^。！？\n]{0,100}(?:平台|系统|项目|服务端)`),
	regexp.MustCompile(`(?i)\b(?:command[- ]and[- ]control|c2)\s+(?:platform|server|framework|system)\b|(?:远程)?指挥控制(?:平台|系统)|c2(?:平台|服务器|框架|系统)`),
	regexp.MustCompile(`(?i)\b(?:agent|endpoint|client|implant|terminal)s?\b[^.!?\n]{0,120}\b(?:execute|run|dispatch|receive)\b[^.!?\n]{0,60}\b(?:commands?|scripts?|tasks?)\b|\b(?:command|task)\s+dispatch\b|(?:终端|代理端|客户端|设备)[^。！？\n]{0,90}(?:执行|接收|下发)[^。！？\n]{0,50}(?:命令|指令|脚本|任务)|(?:指令|命令)下发`),
	regexp.MustCompile(`(?i)\b(?:silent(?:ly)?|hidden\s+window|no\s+window|self[- ]?(?:guard|restart)|daemon(?:ize)?|socks5|nat\s+traversal|proxy\s+tunn?el|reverse\s+tunnel)\b|(?:静默运行|无窗口|自守护|崩溃重启|socks5|nat内网穿透|代理穿透|反向隧道|高性能隧道)`),
}

var securityCodeAuditPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(?:perform|conduct|continue|complete|review|audit|inspect|verify|reproduce)\b[^.!?\n]{0,120}\b(?:security|vulnerabilit(?:y|ies)|fail[- ]?closed|bypass|exploit|mre)\b|\b(?:security|vulnerabilit(?:y|ies)|fail[- ]?closed|bypass|exploit|mre)\b[^.!?\n]{0,120}\b(?:review|audit|inspection|verification|reproduction)\b|(?:只读|静态|安全)?(?:审查|审计|复核|验证)[^。！？\n]{0,100}(?:漏洞|安全|绕过|fail[- ]?closed|mre|伪造)|(?:漏洞|安全|绕过|fail[- ]?closed|mre|伪造)[^。！？\n]{0,100}(?:审查|审计|复核|验证)`),
	regexp.MustCompile(`(?i)\b(?:source\s+code|codebase|scripts?|functions?|verifier|validator|completion\s+gate|sidecar|receipt|tests?|\.go|\.py|\.rs|\.js)\b|(?:源码|代码库|代码|脚本|函数|验证器|校验器|完成门|测试|制品|回执|侧车文件)`),
	regexp.MustCompile(`(?i)\b(?:read[- ]?only|do\s+not\s+modify|without\s+modifying|no\s+code\s+changes|report\s+only|static\s+review)\b|(?:完全)?只读|不(?:要|得)?修改|不改(?:共享)?文件|仅?报告[^。！？\n]{0,24}(?:漏洞|问题)|静态审查`),
	regexp.MustCompile(`(?i)\b(?:toctou|race\s+condition|bypass|tamper|forg(?:e|ed|ery)|spoof|fail[- ]?open|fail[- ]?closed|path\s+traversal|injection|arbitrary\s+error|unsafe\s+deserialization)\b|(?:竞态|绕过|篡改|伪造|漏洞|任意错误|删除文件|缺失文件|失败关闭|保护性失败)`),
}

var loginProtectionReverseEngineeringPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\blogin[\s_-]*p\b|\bp\s+(?:generation|parameter|algorithm|payload)\b[^.!?\n]{0,80}\b(?:login|log[- ]?in|authentication|auth)\b|(?:登录|认证|鉴权)[^。！？\n]{0,60}(?:P值|P参数|P生成|P算法)|(?:P值|P参数|P生成|P算法)[^。！？\n]{0,60}(?:登录|认证|鉴权)`),
	regexp.MustCompile(`(?i)\b(?:obfuscat(?:e|ed|ion)|deobfuscat(?:e|ed|ion)|raw\s+script|eval\s+script|interpreter|virtual\s+machine|vm|opcode|bootstrap)\b|(?:混淆|反混淆|原始脚本|动态脚本|解释器|虚拟机|操作码|引导状态|保护实例)`),
	regexp.MustCompile(`(?i)\b(?:reverse[- ]?engineer(?:ing)?|captur(?:e|es|ed|ing)|replay(?:s|ed|ing)?|locali[sz](?:e|ed|ing|ation)|reimplement(?:s|ed|ing)?|patch(?:es|ed|ing)?|hook(?:s|ed|ing)?|instrument(?:s|ed|ing|ation)?|dump(?:s|ed|ing)?|extract(?:s|ed|ing)?|recover(?:s|ed|ing)?|trace|tracing)\b|(?:逆向|捕获|重放|回放|本地化|重新实现|补丁|钩子|插桩|导出|提取|恢复|追踪|跟踪|改写)`),
}

var loginProtectionOperationalPattern = regexp.MustCompile(`(?i)\b(?:please\s+|help\s+me\s+|need\s+to\s+|continue(?:\s+to)?\s+|now\s+|next\s+step(?:\s+is\s+to)?\s*[:,-]?\s*)(?:verify|test|debug|reverse[- ]?engineer|locali[sz]e|implement|modif(?:y|ies|ied|ying)|fix|generate|run|build|complete|bridge|patch|replay|instrument)\b|\b(?:implement|modif(?:y|ies|ied|ying)|fix|generate|build|complete)\b[^.!?\n]{0,100}\b(?:script|interpreter|vm|patch|hook|tool|code)\b|(?:继续|下一步(?:是)?|现在|请|需要)(?:帮我|我们|去|再|来)?[\s，,:：-]{0,4}(?:验证|测试|调试|逆向|本地化|实现|修改|修复|生成|运行|构建|完成|桥接|补丁|回放|重放|插桩)|(?:实现|修改|修复|生成|构建|完成)[^。！？\n]{0,80}(?:脚本|解释器|虚拟机|VM|补丁|钩子|工具|代码)`)
var loginProtectionNonOperationalSentencePattern = regexp.MustCompile(`(?i)\b(?:summarize|explain|compare|give\s+an\s+overview|analy[sz]e\s+(?:a\s+)?paper)\b[^.!?\n]{0,400}\b(?:do\s+not|without)\b[^.!?\n]{0,160}\b(?:capture|replay|locali[sz]e|implement|patch|hook|reverse[- ]?engineer)\b|(?:总结|解释|对比|概述|分析论文)[^。！？\n]{0,300}(?:不要|无需|不需要)[^。！？\n]{0,120}(?:捕获|重放|回放|本地化|实现|修改|补丁|钩子|逆向)`)
var sentenceSplitter = regexp.MustCompile(`[.!?\n。！？]+`)

var personalMediaCacheDecodePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bwechat\b|微信`),
	regexp.MustCompile(`(?i)\b(?:voice|audio|mp3)\b|(?:收藏|语音|音频|录音|MP3)`),
	regexp.MustCompile(`(?i)\bcach(?:e|ed|es|ing)\b|缓存`),
	regexp.MustCompile(`(?i)\b(?:encrypt(?:ed|ion)?|decrypt(?:s|ed|ing|ion)?|decode(?:s|d|ing|r)?)\b|(?:加密|解密|解码)`),
}

var personalMediaCacheDecodeRequestPattern = regexp.MustCompile(`(?i)\b(?:please|can\s+you|could\s+you|would\s+you|need(?:\s+to)?|want(?:\s+to)?|how\s+to|how\s+(?:can|do|would)\s+i|show\s+me|tell\s+me|help\s+me|provide|write|build|create|batch|bulk|now|continue)\b|(?:请|帮我|告诉我|需要|我要|我想|如何|怎么|怎样|批量|大量|特别多条|能否|能不能|可否|麻烦(?:你)?|可以帮我|现在|继续|接着)`)
var personalMediaCacheDecodeOperationPattern = regexp.MustCompile(`(?i)\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|save(?:s|d|ing)?|convert(?:s|ed|ing|ion)?|decode(?:s|d|ing|r)?|recover(?:s|ed|ing|y)?|find(?:s|ing)?)\b[^.!?,;，；\n]{0,140}\b(?:wechat|voice|audio|mp3|media|cache)\b|\b(?:wechat|voice|audio|mp3|media|cache)\b[^.!?,;，；\n]{0,140}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|save(?:s|d|ing)?|convert(?:s|ed|ing|ion)?|decode(?:s|d|ing|r)?|recover(?:s|ed|ing|y)?|find(?:s|ing)?)\b|(?:找到|提取|导出|保存|存下|转换|转成|解码|恢复)[^。！？,;，；\n]{0,100}(?:微信|收藏|语音|音频|MP3|媒体|缓存)|(?:微信|收藏|语音|音频|MP3|媒体|缓存)[^。！？,;，；\n]{0,100}(?:找到|提取|导出|保存|存下|转换|转成|解码|恢复)`)
var personalMediaCacheDecodeNonOperationalSentencePattern = regexp.MustCompile(`(?i)\b(?:explain|describe|summarize|discuss|review)\b[^.!?,;，；\n]{0,220}\b(?:must|should|do|can)\s+not\b[^.!?,;，；\n]{0,100}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|decode(?:s|d|ing|r)?|convert(?:s|ed|ing|ion)?|recover(?:s|ed|ing|y)?)\b|\b(?:(?:do|must|should|can)\s+not|don['’]t|mustn['’]t|shouldn['’]t|cannot|can['’]t)\b[^.!?,;，；\n]{0,100}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|decode(?:s|d|ing|r)?|convert(?:s|ed|ing|ion)?|recover(?:s|ed|ing|y)?)\b|\b(?:prevent|avoid|stop|block|prohibit|forbid)\b[^.!?,;，；\n]{0,160}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|decode(?:s|d|ing|r)?|convert(?:s|ed|ing|ion)?|recover(?:s|ed|ing|y)?)\b|\b(?:secure|protect)\b[^.!?,;，；\n]{0,100}\b(?:against|from)\b[^.!?,;，；\n]{0,100}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|decode(?:s|d|ing|r)?|convert(?:s|ed|ing|ion)?|recover(?:s|ed|ing|y)?)\b|\b(?:never|without)\b[^.!?,;，；\n]{0,100}\b(?:extract(?:s|ed|ing|ion)?|export(?:s|ed|ing)?|decode(?:s|d|ing|r)?|convert(?:s|ed|ing|ion)?|recover(?:s|ed|ing|y)?)\b|(?:解释|说明|总结|讨论|评估)[^。！？,;，；\n]{0,180}(?:不要|不应|不能|无需|不得|绝不|永不)[^。！？,;，；\n]{0,100}(?:提取|导出|解码|转换|恢复)|(?:不要|不应|不能|无需|不得|绝不|永不|别)[^。！？,;，；\n]{0,100}(?:提取|导出|解码|转换|恢复)|(?:防止|避免|阻止|禁止)[^。！？,;，；\n]{0,120}(?:提取|导出|解码|转换|恢复)|(?:保护)[^。！？,;，；\n]{0,80}(?:免遭|免于|不被|不要被)[^。！？,;，；\n]{0,80}(?:提取|导出|解码|转换|恢复)`)
var personalMediaCacheDecodeClauseBoundaryPattern = regexp.MustCompile(`(?i)\b(?:but|however|then|instead|separately)\b|(?:但是|不过|然而|但|然后|随后|接着|转而)`)

func allWitnessesMatch(text string, patterns []*regexp.Regexp) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	for _, pattern := range patterns {
		if pattern == nil || !pattern.MatchString(text) {
			return false
		}
	}
	return len(patterns) > 0
}

func operationalRansomwareAuthoringVerdict(text string) bool {
	return operationalRansomwareAuthoringRequestPattern.MatchString(text) &&
		allWitnessesMatch(text, operationalRansomwareCapabilityPatterns)
}

func operationalSecurityTestingPlatformVerdict(text string) bool {
	if !allWitnessesMatch(text, operationalSecurityTestingPlatformPatterns) {
		return false
	}
	count := 0
	for _, pattern := range operationalSecurityTestingCapabilityPatterns {
		if pattern.MatchString(text) {
			count++
		}
	}
	return count >= 2
}

func loginProtectionReverseEngineeringVerdict(text string) bool {
	if !allWitnessesMatch(text, loginProtectionReverseEngineeringPatterns) {
		return false
	}
	for _, sentence := range sentenceSplitter.Split(strings.TrimSpace(text), -1) {
		if loginProtectionNonOperationalSentencePattern.MatchString(sentence) {
			continue
		}
		if loginProtectionOperationalPattern.MatchString(sentence) {
			return true
		}
	}
	return false
}

func personalMediaCacheDecodeVerdict(text string) bool {
	sentences := sentenceSplitter.Split(strings.TrimSpace(text), -1)
	for index, sentence := range sentences {
		sentence = strings.TrimSpace(sentence)
		if sentence == "" || !personalMediaCacheDecodeRequestPattern.MatchString(sentence) {
			continue
		}
		operationText := personalMediaCacheDecodeClauseBoundaryPattern.ReplaceAllString(sentence, ",")
		operations := personalMediaCacheDecodeOperationPattern.FindAllStringIndex(operationText, -1)
		if len(operations) == 0 {
			continue
		}
		negativeRanges := personalMediaCacheDecodeNonOperationalSentencePattern.FindAllStringIndex(operationText, -1)
		hasUnnegatedOperation := false
		for _, operation := range operations {
			negated := false
			for _, negativeRange := range negativeRanges {
				if negativeRange[0] >= len("能") &&
					strings.HasSuffix(operationText[:negativeRange[0]], "能") &&
					strings.HasPrefix(operationText[negativeRange[0]:negativeRange[1]], "不能") {
					continue
				}
				if operation[0] < negativeRange[1] && negativeRange[0] < operation[1] {
					negated = true
					break
				}
			}
			if !negated {
				hasUnnegatedOperation = true
				break
			}
		}
		if !hasUnnegatedOperation {
			continue
		}
		start := index - 1
		if start < 0 {
			start = 0
		}
		end := index + 2
		if end > len(sentences) {
			end = len(sentences)
		}
		if allWitnessesMatch(strings.Join(sentences[start:end], " "), personalMediaCacheDecodePatterns) {
			return true
		}
	}
	return false
}

func observedGapSignals(text string) []string {
	var signals []string
	if allWitnessesMatch(text, ctfFlagExploitationPatterns) {
		signals = append(signals, SignalCTFFlagExploitation)
	}
	if operationalSecurityTestingPlatformVerdict(text) {
		signals = append(signals, SignalOperationalSecurityTesting)
	}
	if operationalRansomwareAuthoringVerdict(text) {
		signals = append(signals, SignalOperationalRansomwareAuthoring)
	}
	if allWitnessesMatch(text, mlModelBackdoorTrainingPatterns) {
		signals = append(signals, SignalMLModelBackdoorTraining)
	}
	if allWitnessesMatch(text, remoteCommandControlPlatformPatterns) {
		signals = append(signals, SignalRemoteCommandControlPlatform)
	}
	if allWitnessesMatch(text, securityCodeAuditPatterns) {
		signals = append(signals, SignalSecurityCodeAudit)
	}
	if loginProtectionReverseEngineeringVerdict(text) {
		signals = append(signals, SignalLoginProtectionReverseEngineering)
	}
	if personalMediaCacheDecodeVerdict(text) {
		signals = append(signals, SignalPersonalMediaCacheDecode)
	}
	return signals
}
