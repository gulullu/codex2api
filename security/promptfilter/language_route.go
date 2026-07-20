package promptfilter

import (
	"hash/maphash"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	nonZhEnMinimumForeignScriptLetters = 4
	nonZhEnStrongForeignScriptLetters  = 12
	nonZhEnLatinWindowBytes            = 1024
	nonZhEnLatinWindowOverlapBytes     = 256
	nonZhEnLanguageCacheMinBytes       = 256
	nonZhEnLanguageCacheEntries        = 8192
)

type nonZhEnLanguageCacheKey struct {
	first  uint64
	second uint64
	length int
	domain uint8
}

const (
	nonZhEnCacheDomainFullPartition uint8 = iota
	nonZhEnCacheDomainLatinWindow
)

type nonZhEnLanguageDecisionCache struct {
	mu      sync.RWMutex
	entries map[nonZhEnLanguageCacheKey]bool
	order   []nonZhEnLanguageCacheKey
	next    int
}

var nonZhEnLanguageCache = nonZhEnLanguageDecisionCache{
	entries: make(map[nonZhEnLanguageCacheKey]bool, nonZhEnLanguageCacheEntries),
	order:   make([]nonZhEnLanguageCacheKey, 0, nonZhEnLanguageCacheEntries),
}

var (
	nonZhEnLanguageHashSeedFirst  = maphash.MakeSeed()
	nonZhEnLanguageHashSeedSecond = maphash.MakeSeed()
)

type latinLanguageMarkerGroup struct {
	strong []string
	weak   []string
}

// nonEnglishLatinMarkerGroups are deliberately high-precision prose marker
// groups. Statistical language detectors are intentionally not used here:
// code, paths, identifiers, tool schemas, and sports names can receive
// confidently wrong language labels. Generic short words, accents, product
// names, and identifiers cannot decide routing by themselves.
var nonEnglishLatinMarkerGroups = []latinLanguageMarkerGroup{
	{strong: []string{"hola", "gracias", "revisa", "respuesta", "explica", "solicitud", "porque", "necesito", "instrucciones", "detalladas", "vigilancia", "secreta", "consentimiento", "incluyendo", "seguimiento", "ubicacion", "comunicaciones"}, weak: []string{"para", "esta", "este", "una", "sin", "sobre", "con", "que"}},
	{strong: []string{"bonjour", "merci", "pourquoi", "requete", "requête", "reponse", "réponse", "expliquez", "verifiez", "vérifiez", "demande", "echoue", "échoué"}, weak: []string{"avec", "pour", "dans", "cette", "une", "sans", "sur", "que"}},
	{strong: []string{"bitte", "warum", "antwort", "anfrage", "prüfen", "pruefen", "erklären", "erklaeren", "fehlgeschlagen"}, weak: []string{"nicht", "diese", "dieser", "eine", "ohne", "und", "ist"}},
	{strong: []string{"obrigado", "resposta", "solicitacao", "solicitação", "explique", "revise", "verifique", "falhou"}, weak: []string{"porque", "para", "esta", "uma", "sem", "sobre", "voce", "você", "nao", "não"}},
	{strong: []string{"ciao", "grazie", "spiega", "richiesta", "risposta", "controlla", "perche", "perché", "riuscita"}, weak: []string{"questa", "questo", "una", "senza", "non", "che", "per"}},
	{strong: []string{"alstublieft", "waarom", "antwoord", "verzoek", "controleer", "uitleggen", "mislukt"}, weak: []string{"deze", "voor", "niet", "met", "een", "zonder", "het", "dat"}},
	{strong: []string{"proszę", "prosze", "dlaczego", "odpowiedz", "odpowiedź", "żądanie", "zadanie", "sprawdź", "sprawdz", "wyjaśnij", "wyjasnij"}, weak: []string{"jest", "oraz", "nie", "dla", "bez"}},
	{strong: []string{"lütfen", "lutfen", "neden", "istek", "istegin", "yanıt", "yanit", "yanitini", "kontrol", "açıkla", "acikla", "aciklayin", "basarisiz", "başarısız"}, weak: []string{"için", "icin", "değil", "degil", "bir", "ve", "bu"}},
	{strong: []string{"tolong", "mengapa", "permintaan", "jawaban", "periksa", "jelaskan", "gagal"}, weak: []string{"dengan", "untuk", "yang", "tidak", "ini", "dan", "tanpa"}},
	{strong: []string{"sila", "mengapa", "permintaan", "jawapan", "semak", "jelaskan", "gagal"}, weak: []string{"dengan", "untuk", "yang", "tidak", "ini", "dan", "tanpa"}},
	{strong: []string{"vui long", "vui lòng", "kiem tra", "kiểm tra", "phan hoi", "phản hồi", "giai thich", "giải thích", "tai sao", "tại sao", "yeu cau", "yêu cầu", "that bai", "thất bại"}, weak: []string{"khong", "không", "mot", "một", "va", "và", "nay", "này"}},
	{strong: []string{"va rog", "vă rog", "de ce", "raspuns", "răspuns", "cerere", "verifica", "explica", "esuat", "eșuat"}, weak: []string{"pentru", "acest", "aceasta", "fara", "fără", "este"}},
	{strong: []string{"prosím", "prosim", "proč", "proc", "odpověď", "odpoved", "požadavek", "pozadavek", "zkontrolujte", "vysvětlete", "vysvetlete", "selhal"}, weak: []string{"tento", "tato", "bez", "není", "neni", "pro"}},
	{strong: []string{"prosím", "prosim", "prečo", "preco", "odpoveď", "odpoved", "požiadavka", "poziadavka", "skontrolujte", "vysvetlite", "zlyhala"}, weak: []string{"tento", "tato", "bez", "nie", "pre"}},
	{strong: []string{"kérem", "kerem", "miért", "miert", "válasz", "valasz", "kérés", "keres", "ellenőrizze", "ellenorizze", "magyarázza", "magyarazza", "sikertelen"}, weak: []string{"ezt", "nem", "és", "es", "nélkül", "nelkul", "egy"}},
	{strong: []string{"vänligen", "vanligen", "varför", "varfor", "svar", "begäran", "begaran", "kontrollera", "förklara", "forklara", "misslyckades"}, weak: []string{"denna", "inte", "med", "för", "for", "utan", "och"}},
	{strong: []string{"venligst", "hvorfor", "svar", "anmodning", "kontrollér", "kontroller", "forklar", "mislykkedes"}, weak: []string{"denne", "ikke", "med", "for", "uden", "og"}},
	{strong: []string{"vennligst", "hvorfor", "svar", "forespørsel", "foresporsel", "kontroller", "forklar", "mislyktes"}, weak: []string{"denne", "ikke", "med", "for", "uten", "og"}},
	{strong: []string{"ole hyvä", "ole hyva", "miksi", "vastaus", "pyyntö", "pyynto", "tarkista", "selitä", "selita", "epäonnistui", "epaonnistui"}, weak: []string{"tämä", "tama", "ei", "kanssa", "varten", "ilman", "ja"}},
	{strong: []string{"si us plau", "per què", "per que", "resposta", "sol·licitud", "sollicitud", "comprova", "explica", "fallat"}, weak: []string{"aquesta", "sense", "amb", "no"}},
	{strong: []string{"molim", "zašto", "zasto", "odgovor", "zahtjev", "provjerite", "objasnite", "nije uspio"}, weak: []string{"ovaj", "ova", "bez", "nije", "za"}},
	{strong: []string{"palun", "miks", "vastus", "päring", "paring", "kontrollige", "selgitage", "ebaõnnestus", "ebaonnestus"}, weak: []string{"see", "ei", "koos", "jaoks", "ilma"}},
	{strong: []string{"lūdzu", "ludzu", "kāpēc", "kapec", "atbilde", "pieprasījums", "pieprasijums", "pārbaudiet", "parbaudiet", "paskaidrojiet", "neizdevās", "neizdevas"}, weak: []string{"šis", "sis", "šī", "si", "bez", "nav", "par"}},
	{strong: []string{"prašau", "prasau", "kodėl", "kodel", "atsakymas", "užklausa", "uzklausa", "patikrinkite", "paaiškinkite", "paaiskinkite", "nepavyko"}, weak: []string{"šis", "sis", "ši", "si", "be", "nėra", "nera", "dėl", "del"}},
	{strong: []string{"asseblief", "waarom", "antwoord", "versoek", "kontroleer", "verduidelik", "misluk"}, weak: []string{"hierdie", "nie", "met", "vir", "sonder"}},
	{strong: []string{"tafadhali", "kwa nini", "jibu", "ombi", "angalia", "eleza", "imeshindwa"}, weak: []string{"hii", "bila", "na", "kwa"}},
	{strong: []string{"pakitingnan", "bakit", "sagot", "kahilingan", "suriin", "ipaliwanag", "nabigo"}, weak: []string{"ito", "hindi", "para", "nang", "na"}},
}

// LooksLikeNonChineseEnglishNaturalLanguage reports whether bounded readable
// prompt text contains enough evidence of a natural language other than
// Chinese or English. It is a routing hint only: callers must never use it to
// block a request. URL/path/hash/code noise is excluded before the Latin marker
// pass; recognized non-Latin Unicode scripts are covered independently.
func LooksLikeNonChineseEnglishNaturalLanguage(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	if len(text) < nonZhEnLanguageCacheMinBytes {
		return containsForeignNaturalScript(text) || containsForeignLatinNaturalLanguage(text)
	}
	key := newNonZhEnLanguageCacheKey(text, nonZhEnCacheDomainFullPartition)
	if result, ok := nonZhEnLanguageCache.get(key); ok {
		return result
	}
	result := containsForeignNaturalScript(text) || containsForeignLatinNaturalLanguage(text)
	nonZhEnLanguageCache.put(key, result)
	return result
}

func newNonZhEnLanguageCacheKey(text string, domain uint8) nonZhEnLanguageCacheKey {
	var first, second maphash.Hash
	first.SetSeed(nonZhEnLanguageHashSeedFirst)
	second.SetSeed(nonZhEnLanguageHashSeedSecond)
	_, _ = first.WriteString(text)
	_, _ = second.WriteString(text)
	return nonZhEnLanguageCacheKey{first: first.Sum64(), second: second.Sum64(), length: len(text), domain: domain}
}

func (cache *nonZhEnLanguageDecisionCache) get(key nonZhEnLanguageCacheKey) (bool, bool) {
	cache.mu.RLock()
	result, ok := cache.entries[key]
	cache.mu.RUnlock()
	return result, ok
}

func (cache *nonZhEnLanguageDecisionCache) put(key nonZhEnLanguageCacheKey, result bool) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if _, exists := cache.entries[key]; exists {
		return
	}
	if len(cache.order) < cap(cache.order) {
		cache.order = append(cache.order, key)
	} else {
		delete(cache.entries, cache.order[cache.next])
		cache.order[cache.next] = key
		cache.next = (cache.next + 1) % len(cache.order)
	}
	cache.entries[key] = result
}

func containsForeignNaturalScript(text string) bool {
	type scriptEvidence struct {
		meaningfulLetters int
		meaningfulWords   int
		longestWord       int
	}
	var evidence [foreignScriptCount]scriptEvidence
	totalLetters := 0
	activeScript := -1
	activeWordLetters := 0
	flushWord := func() {
		if activeScript < 0 || activeWordLetters < 2 {
			activeScript = -1
			activeWordLetters = 0
			return
		}
		current := &evidence[activeScript]
		current.meaningfulLetters += activeWordLetters
		current.meaningfulWords++
		if activeWordLetters > current.longestWord {
			current.longestWord = activeWordLetters
		}
		activeScript = -1
		activeWordLetters = 0
	}
	for _, line := range strings.Split(text, "\n") {
		for _, segment := range naturalLanguageSegmentsFromLine(line) {
			for _, field := range strings.Fields(segment) {
				if machineLikeLanguageToken(field) {
					flushWord()
					continue
				}
				for _, r := range field {
					if unicode.Is(unicode.Mn, r) && activeScript >= 0 {
						continue
					}
					if !unicode.IsLetter(r) {
						flushWord()
						continue
					}
					totalLetters++
					if unicode.Is(unicode.Han, r) || unicode.Is(unicode.Latin, r) || unicode.Is(unicode.Bopomofo, r) {
						flushWord()
						continue
					}
					bucket := foreignScriptBucket(r)
					if activeScript != bucket {
						flushWord()
						activeScript = bucket
					}
					activeWordLetters++
				}
				flushWord()
			}
		}
	}
	if totalLetters == 0 {
		return false
	}
	for bucket, current := range evidence {
		if current.meaningfulLetters < nonZhEnMinimumForeignScriptLetters {
			continue
		}
		strongInPartition := current.meaningfulLetters >= nonZhEnStrongForeignScriptLetters || current.meaningfulLetters*8 >= totalLetters
		switch bucket {
		case foreignScriptGreek:
			// Greek math variables and repeated scientific units such as μL/μM
			// are isolated one-letter runs and therefore never qualify here.
			if current.meaningfulWords >= 3 && current.meaningfulLetters >= 8 && strongInPartition {
				return true
			}
		case foreignScriptKana, foreignScriptThai, foreignScriptLao, foreignScriptKhmer, foreignScriptMyanmar:
			// These scripts commonly omit spaces or are split by allowed Han
			// characters, so coherent script volume is the safer boundary.
			if current.meaningfulLetters >= nonZhEnStrongForeignScriptLetters ||
				(current.meaningfulLetters >= 8 && current.meaningfulLetters*8 >= totalLetters) {
				return true
			}
		case foreignScriptHangul:
			if current.meaningfulLetters >= 8 && (current.meaningfulWords >= 2 || current.meaningfulLetters >= nonZhEnStrongForeignScriptLetters) {
				return true
			}
		default:
			// Spaced scripts require at least three real words. This excludes
			// one- and two-part personal names and code identifiers while retaining
			// prose. Three title-cased words remain decisive: suppressing them
			// globally would create a trivial Title Case bypass for short commands.
			if current.meaningfulWords >= 3 && current.meaningfulLetters >= 8 && strongInPartition {
				return true
			}
		}
	}
	return false
}

const (
	foreignScriptCyrillic = iota
	foreignScriptArabic
	foreignScriptDevanagari
	foreignScriptHebrew
	foreignScriptGreek
	foreignScriptKana
	foreignScriptHangul
	foreignScriptThai
	foreignScriptBengali
	foreignScriptGeorgian
	foreignScriptArmenian
	foreignScriptEthiopic
	foreignScriptGujarati
	foreignScriptGurmukhi
	foreignScriptKannada
	foreignScriptTamil
	foreignScriptTelugu
	foreignScriptMalayalam
	foreignScriptOriya
	foreignScriptMyanmar
	foreignScriptSinhala
	foreignScriptKhmer
	foreignScriptLao
	foreignScriptTibetan
	foreignScriptSyriac
	foreignScriptThaana
	foreignScriptCherokee
	foreignScriptCanadianAboriginal
	foreignScriptMongolian
	foreignScriptCount
)

func foreignScriptBucket(r rune) int {
	switch {
	case unicode.Is(unicode.Cyrillic, r):
		return foreignScriptCyrillic
	case unicode.Is(unicode.Arabic, r):
		return foreignScriptArabic
	case unicode.Is(unicode.Devanagari, r):
		return foreignScriptDevanagari
	case unicode.Is(unicode.Hebrew, r):
		return foreignScriptHebrew
	case unicode.Is(unicode.Greek, r):
		return foreignScriptGreek
	case unicode.Is(unicode.Hiragana, r) || unicode.Is(unicode.Katakana, r):
		return foreignScriptKana
	case unicode.Is(unicode.Hangul, r):
		return foreignScriptHangul
	case unicode.Is(unicode.Thai, r):
		return foreignScriptThai
	case unicode.Is(unicode.Bengali, r):
		return foreignScriptBengali
	case unicode.Is(unicode.Georgian, r):
		return foreignScriptGeorgian
	case unicode.Is(unicode.Armenian, r):
		return foreignScriptArmenian
	case unicode.Is(unicode.Ethiopic, r):
		return foreignScriptEthiopic
	case unicode.Is(unicode.Gujarati, r):
		return foreignScriptGujarati
	case unicode.Is(unicode.Gurmukhi, r):
		return foreignScriptGurmukhi
	case unicode.Is(unicode.Kannada, r):
		return foreignScriptKannada
	case unicode.Is(unicode.Tamil, r):
		return foreignScriptTamil
	case unicode.Is(unicode.Telugu, r):
		return foreignScriptTelugu
	case unicode.Is(unicode.Malayalam, r):
		return foreignScriptMalayalam
	case unicode.Is(unicode.Oriya, r):
		return foreignScriptOriya
	case unicode.Is(unicode.Myanmar, r):
		return foreignScriptMyanmar
	case unicode.Is(unicode.Sinhala, r):
		return foreignScriptSinhala
	case unicode.Is(unicode.Khmer, r):
		return foreignScriptKhmer
	case unicode.Is(unicode.Lao, r):
		return foreignScriptLao
	case unicode.Is(unicode.Tibetan, r):
		return foreignScriptTibetan
	case unicode.Is(unicode.Syriac, r):
		return foreignScriptSyriac
	case unicode.Is(unicode.Thaana, r):
		return foreignScriptThaana
	case unicode.Is(unicode.Cherokee, r):
		return foreignScriptCherokee
	case unicode.Is(unicode.Canadian_Aboriginal, r):
		return foreignScriptCanadianAboriginal
	case unicode.Is(unicode.Mongolian, r):
		return foreignScriptMongolian
	default:
		// Never merge unrelated unknown scripts into one evidence bucket.
		return -1
	}
}

func containsForeignLatinNaturalLanguage(text string) bool {
	var shortLines strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if containsForeignLatinSpan(line) {
			return true
		}
		if len(line) == 0 || len(line) >= nonZhEnLatinWindowOverlapBytes {
			continue
		}
		if shortLines.Len() > 0 {
			shortLines.WriteByte('\n')
		}
		shortLines.WriteString(line)
		if shortLines.Len() >= nonZhEnLatinWindowBytes {
			if containsForeignLatinSpan(shortLines.String()) {
				return true
			}
			shortLines.Reset()
		}
	}
	return shortLines.Len() > 0 && containsForeignLatinSpan(shortLines.String())
}

func containsForeignLatinSpan(text string) bool {
	for start := 0; start < len(text); {
		end := start + nonZhEnLatinWindowBytes
		if end >= len(text) {
			end = len(text)
		} else {
			for end > start && !utf8.RuneStart(text[end]) {
				end--
			}
		}
		if containsForeignLatinWindow(text[start:end]) {
			return true
		}
		if end == len(text) {
			break
		}
		next := end - nonZhEnLatinWindowOverlapBytes
		for next < end && !utf8.RuneStart(text[next]) {
			next++
		}
		if next <= start {
			next = end
		}
		start = next
	}
	return false
}

func containsForeignLatinWindow(text string) bool {
	if len(text) >= nonZhEnLanguageCacheMinBytes {
		key := newNonZhEnLanguageCacheKey(text, nonZhEnCacheDomainLatinWindow)
		if result, ok := nonZhEnLanguageCache.get(key); ok {
			return result
		}
		result := inspectForeignLatinWindow(text)
		nonZhEnLanguageCache.put(key, result)
		return result
	}
	return inspectForeignLatinWindow(text)
}

func inspectForeignLatinWindow(text string) bool {
	allWords := latinNaturalLanguageWords(text)
	if len(allWords) == 0 {
		return false
	}
	return hasNonEnglishLatinMarkers(allWords)
}

func latinNaturalLanguageWords(text string) []string {
	var allWords []string
	for _, line := range strings.Split(text, "\n") {
		allWords = append(allWords, latinWordsFromLine(line)...)
	}
	return allWords
}

func latinWordsFromLine(line string) []string {
	if strings.TrimSpace(line) == "" {
		return nil
	}
	words := make([]string, 0, 16)
	for _, segment := range naturalLanguageSegmentsFromLine(line) {
		for _, field := range strings.Fields(segment) {
			if machineLikeLanguageToken(field) {
				continue
			}
			for _, word := range latinWords(field) {
				if machineLikeLanguageWord(word) {
					continue
				}
				wordRunes := utf8.RuneCountInString(word)
				if wordRunes < 2 || wordRunes > 30 {
					continue
				}
				words = append(words, word)
			}
		}
	}
	return words
}

// naturalLanguageSegmentsFromLine removes source-code identifiers from the
// language decision while retaining quoted strings and comments, where prose
// can legitimately live. The check is intentionally narrow: arbitrary JSON,
// Markdown, and slash-separated adversarial prose must not become a bypass.
func naturalLanguageSegmentsFromLine(line string) []string {
	if !looksLikeSourceCodeLine(line) {
		return []string{line}
	}
	return sourceCodeProseSegments(line)
}

func looksLikeSourceCodeLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	prefixes := []string{
		"const ", "var ", "let ", "func ", "function ", "def ", "class ",
		"type ", "package ", "import ", "from ", "public ", "private ",
		"protected ", "interface ", "struct ", "enum ",
	}
	matchedPrefix := false
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			matchedPrefix = true
			break
		}
	}
	return matchedPrefix && strings.ContainsAny(trimmed, "={}();`")
}

func sourceCodeProseSegments(line string) []string {
	segments := make([]string, 0, 3)
	var quoted strings.Builder
	var quote rune
	escaped := false
	for _, r := range line {
		if quote == 0 {
			if r == '\'' || r == '"' || r == '`' {
				quote = r
				quoted.Reset()
			}
			continue
		}
		if escaped {
			quoted.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == quote {
			if value := strings.TrimSpace(quoted.String()); value != "" {
				segments = append(segments, value)
			}
			quote = 0
			continue
		}
		quoted.WriteRune(r)
	}
	if comment := sourceCodeLineComment(line); comment != "" {
		segments = append(segments, comment)
	}
	return segments
}

func sourceCodeLineComment(line string) string {
	var quote byte
	escaped := false
	for index := 0; index < len(line); index++ {
		current := line[index]
		if quote != 0 {
			if escaped {
				escaped = false
				continue
			}
			if current == '\\' {
				escaped = true
				continue
			}
			if current == quote {
				quote = 0
			}
			continue
		}
		if current == '\'' || current == '"' || current == '`' {
			quote = current
			continue
		}
		if current == '/' && index+1 < len(line) && line[index+1] == '/' {
			return strings.TrimSpace(line[index+2:])
		}
		if current == '#' && (index == 0 || line[index-1] == ' ' || line[index-1] == '\t') {
			return strings.TrimSpace(line[index+1:])
		}
	}
	return ""
}

func machineLikeLanguageToken(token string) bool {
	trimmed := strings.Trim(token, "\"'.,!?，。！？:：()")
	lower := strings.ToLower(trimmed)
	if lower == "" || strings.Contains(lower, "://") || strings.HasPrefix(lower, "www.") {
		return true
	}
	if len(lower) >= 3 && ((lower[0] >= 'a' && lower[0] <= 'z') && lower[1] == ':' && (lower[2] == '\\' || lower[2] == '/')) {
		return true
	}
	separatorCount := strings.Count(lower, "/") + strings.Count(lower, `\`)
	if separatorCount >= 2 && relativeFilePathToken(lower) {
		return true
	}
	return strings.HasPrefix(lower, "/") || strings.HasPrefix(lower, "./") ||
		strings.HasPrefix(lower, "../") || strings.HasPrefix(lower, "~/") || strings.HasPrefix(lower, `\\`)
}

func relativeFilePathToken(token string) bool {
	normalized := strings.ReplaceAll(token, `\`, "/")
	leaf := strings.Trim(normalized[strings.LastIndex(normalized, "/")+1:], `"'.,!?;:()[]{}`)
	dot := strings.LastIndexByte(leaf, '.')
	if dot <= 0 || len(leaf)-dot-1 < 1 || len(leaf)-dot-1 > 12 {
		return false
	}
	for _, r := range leaf[dot+1:] {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func machineLikeLanguageWord(word string) bool {
	switch word {
	case "fail", "failed", "failure", "error", "errors", "pass", "passed", "success", "unknown", "panic", "traceback", "code", "message", "status",
		"instruction", "instructions", "environment", "context", "cwd", "shell", "current", "date", "timezone", "time", "asia", "shanghai",
		"pf", "hit", "powershell", "npm", "lint", "validated", "behavior", "latest", "checks", "test", "tests", "build", "slow",
		"codex", "users", "documents":
		return true
	default:
		return false
	}
}

func latinWords(value string) []string {
	var words []string
	var current strings.Builder
	previousLower := false
	flush := func() {
		if current.Len() == 0 {
			return
		}
		words = append(words, strings.ToLower(current.String()))
		current.Reset()
		previousLower = false
	}
	for _, r := range value {
		if unicode.Is(unicode.Latin, r) {
			if current.Len() > 0 && unicode.IsUpper(r) && previousLower {
				flush()
			}
			current.WriteRune(r)
			previousLower = unicode.IsLower(r)
			continue
		}
		if current.Len() > 0 && unicode.Is(unicode.Mn, r) {
			current.WriteRune(r)
			continue
		}
		flush()
	}
	flush()
	return words
}

func hasNonEnglishLatinMarkers(words []string) bool {
	seenWords := make(map[string]struct{}, len(words))
	for _, word := range words {
		seenWords[word] = struct{}{}
	}
	joined := " " + strings.Join(words, " ") + " "
	for _, group := range nonEnglishLatinMarkerGroups {
		seenMarkers := make(map[string]struct{}, 6)
		strongCount, phraseCount := 0, 0
		for _, marker := range group.strong {
			if !latinMarkerMatches(marker, seenWords, joined) {
				continue
			}
			seenMarkers[marker] = struct{}{}
			strongCount++
			if strings.Contains(marker, " ") {
				phraseCount++
			}
		}
		for _, marker := range group.weak {
			if latinMarkerMatches(marker, seenWords, joined) {
				seenMarkers[marker] = struct{}{}
			}
		}
		if (len(seenMarkers) >= 4 && strongCount >= 3) ||
			(len(seenMarkers) >= 3 && strongCount >= 2 && phraseCount >= 1) {
			return true
		}
	}
	return false
}

func latinMarkerMatches(marker string, seenWords map[string]struct{}, joined string) bool {
	if strings.Contains(marker, " ") {
		return strings.Contains(joined, " "+marker+" ")
	}
	_, matched := seenWords[marker]
	return matched
}
