package cybroute

import "github.com/codex2api/security/promptfilter"

// These official moderation rules are not reliable predictors of an upstream
// CYB rejection. They remain available to the official prompt-filter feature;
// only this routing-only view disables them.
var nonCYBRoutePatterns = []string{
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

// These are the five RelayBases production patterns that do not exist in the
// current official rule set. Same-name caller patterns win, allowing an
// operator to tune them through the existing official configuration.
var productionPatternConfigs = []promptfilter.PatternConfig{
	{
		Name:     "malware_authoring",
		Pattern:  `(?i)\b(write|create|generate|build|develop|code|program|make)\b[^.!?\n]{0,50}\b(malware|virus|trojan|worm|ransomware|spyware|info[-\s]?stealer|stealer|rootkit|\brat\b|remote\s+access\s+trojan|bootkit|wiper)\b|(?:写|编写|生成|制作|开发)[^。！？\n]{0,30}(恶意软件|病毒|木马|蠕虫|勒索软件|间谍软件|窃密程序)`,
		Weight:   90,
		Category: "malware",
		Strict:   true,
	},
	{
		Name:     "mfa_bypass",
		Pattern:  `(?i)\b(bypass|defeat|circumvent|disable|get\s+around)\b[^.!?\n]{0,30}\b(2fa|mfa|two[-\s]?factor|multi[-\s]?factor|otp|one[-\s]?time\s+password|authenticator)\b|绕过[^。！？\n]{0,20}(二次验证|双因素|两步验证|otp|验证码)`,
		Weight:   70,
		Category: "credential_attack",
		Strict:   true,
	},
	{
		Name:     "phishing_generation",
		Pattern:  `(?i)\b(write|generate|create|draft|compose|craft)\b[^.!?\n]{0,40}\b(phishing|spear[-\s]?phishing|smishing|scam)\b[^.!?\n]{0,20}\b(email|e-mail|message|sms|text|page|template|lure)\b|(?:写|生成|制作|起草)[^。！？\n]{0,30}(钓鱼|诈骗)[^。！？\n]{0,15}(邮件|短信|页面|模板)`,
		Weight:   75,
		Category: "social_engineering",
		Strict:   true,
	},
	{
		Name:     "fraud_carding",
		Pattern:  `(?i)\b(carding|card\s+dumps?|cvv\s+dumps?|dumps?\s+(?:with|and)\s+pins?|fullz|bank\s+drops?|cashout\s+(?:method|guide))\b|信用卡盗刷|盗刷教程`,
		Weight:   70,
		Category: "fraud",
		Strict:   true,
	},
	{
		Name:     "spam_automation",
		Pattern:  `(?i)\b(mass|bulk|automated)\b[^.!?\n]{0,20}\b(spam|unsolicited\s+email|robocall|sms\s+blast)\b|群发[^。！？\n]{0,15}(垃圾邮件|短信|骚扰)`,
		Weight:   35,
		Category: "abuse",
	},
}
