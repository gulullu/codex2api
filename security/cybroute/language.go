package cybroute

import (
	"strings"
	"unicode"
)

type latinMarkerGroup struct {
	strong []string
	weak   []string
}

// High-precision prose markers retained from the production routing rule.
// Generic accents, names, product names and identifiers are not decisive.
var nonEnglishLatinMarkerGroups = []latinMarkerGroup{
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

func looksLikeNonChineseEnglishNaturalLanguage(text string) bool {
	if strings.TrimSpace(text) == "" {
		return false
	}
	segments := proseSegments(text)
	if foreignScriptProse(segments) {
		return true
	}
	words := latinProseWords(segments)
	if len(words) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(words))
	for _, word := range words {
		seen[word] = struct{}{}
	}
	joined := " " + strings.Join(words, " ") + " "
	for _, group := range nonEnglishLatinMarkerGroups {
		markers := make(map[string]struct{})
		strong, phrases := 0, 0
		for _, marker := range group.strong {
			if !latinMarkerMatches(marker, seen, joined) {
				continue
			}
			markers[marker] = struct{}{}
			strong++
			if strings.Contains(marker, " ") {
				phrases++
			}
		}
		for _, marker := range group.weak {
			if latinMarkerMatches(marker, seen, joined) {
				markers[marker] = struct{}{}
			}
		}
		if (len(markers) >= 4 && strong >= 3) ||
			(len(markers) >= 3 && strong >= 2 && phrases >= 1) {
			return true
		}
	}
	return false
}

func latinMarkerMatches(marker string, seen map[string]struct{}, joined string) bool {
	if strings.Contains(marker, " ") {
		return strings.Contains(joined, " "+marker+" ")
	}
	_, ok := seen[marker]
	return ok
}

func proseSegments(text string) []string {
	var segments []string
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if looksLikeSourceLine(trimmed) {
			segments = append(segments, sourceLineProse(trimmed)...)
			continue
		}
		fields := strings.Fields(trimmed)
		var kept strings.Builder
		for _, field := range fields {
			if machineLikeToken(field) {
				continue
			}
			if kept.Len() > 0 {
				kept.WriteByte(' ')
			}
			kept.WriteString(field)
		}
		if kept.Len() > 0 {
			segments = append(segments, kept.String())
		}
	}
	return segments
}

func looksLikeSourceLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	for _, prefix := range []string{
		"const ", "var ", "let ", "func ", "function ", "def ", "class ",
		"type ", "package ", "import ", "from ", "public ", "private ",
		"protected ", "interface ", "struct ", "enum ",
	} {
		if strings.HasPrefix(lower, prefix) && strings.ContainsAny(line, "={}();`") {
			return true
		}
	}
	return false
}

func sourceLineProse(line string) []string {
	var out []string
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
				out = append(out, value)
			}
			quote = 0
			continue
		}
		quoted.WriteRune(r)
	}
	if index := strings.Index(line, "//"); index >= 0 {
		if value := strings.TrimSpace(line[index+2:]); value != "" {
			out = append(out, value)
		}
	} else if index := strings.Index(line, "#"); index >= 0 {
		if value := strings.TrimSpace(line[index+1:]); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func machineLikeToken(value string) bool {
	token := strings.Trim(value, "\"'.,!?，。！？:：()[]{}")
	lower := strings.ToLower(token)
	if lower == "" || strings.Contains(lower, "://") || strings.HasPrefix(lower, "www.") {
		return true
	}
	if len(lower) >= 3 && unicode.IsLetter(rune(lower[0])) && lower[1] == ':' &&
		(lower[2] == '\\' || lower[2] == '/') {
		return true
	}
	normalized := strings.ReplaceAll(lower, `\`, "/")
	if strings.Count(normalized, "/") >= 2 {
		leaf := normalized[strings.LastIndex(normalized, "/")+1:]
		if dot := strings.LastIndexByte(leaf, '.'); dot > 0 && len(leaf)-dot <= 13 {
			return true
		}
	}
	return strings.HasPrefix(lower, "/") || strings.HasPrefix(lower, "./") ||
		strings.HasPrefix(lower, "../") || strings.HasPrefix(lower, "~/") ||
		strings.HasPrefix(lower, `\\`)
}

func latinProseWords(segments []string) []string {
	var words []string
	for _, segment := range segments {
		var current strings.Builder
		previousLower := false
		flush := func() {
			if current.Len() == 0 {
				return
			}
			value := strings.ToLower(current.String())
			current.Reset()
			previousLower = false
			if len([]rune(value)) >= 2 && len([]rune(value)) <= 30 && !machineWord(value) {
				words = append(words, value)
			}
		}
		for _, r := range segment {
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
	}
	return words
}

func machineWord(word string) bool {
	switch word {
	case "fail", "failed", "failure", "error", "errors", "pass", "passed", "success", "unknown",
		"panic", "traceback", "code", "message", "status", "instruction", "instructions",
		"environment", "context", "cwd", "shell", "current", "date", "timezone", "time",
		"asia", "shanghai", "pf", "hit", "powershell", "npm", "lint", "validated",
		"behavior", "latest", "checks", "test", "tests", "build", "slow", "codex",
		"users", "documents":
		return true
	default:
		return false
	}
}

type scriptEvidence struct {
	letters int
	words   int
	longest int
}

func foreignScriptProse(segments []string) bool {
	evidence := make(map[*unicode.RangeTable]*scriptEvidence)
	totalLetters := 0
	for _, segment := range segments {
		for _, field := range strings.Fields(segment) {
			if machineLikeToken(field) {
				continue
			}
			var active *unicode.RangeTable
			activeLetters := 0
			flush := func() {
				if active != nil && activeLetters >= 2 {
					item := evidence[active]
					if item == nil {
						item = &scriptEvidence{}
						evidence[active] = item
					}
					item.letters += activeLetters
					item.words++
					if activeLetters > item.longest {
						item.longest = activeLetters
					}
				}
				active = nil
				activeLetters = 0
			}
			for _, r := range field {
				if unicode.Is(unicode.Mn, r) && active != nil {
					continue
				}
				if !unicode.IsLetter(r) {
					flush()
					continue
				}
				totalLetters++
				script := foreignScript(r)
				if script == nil {
					flush()
					continue
				}
				if active != script {
					flush()
					active = script
				}
				activeLetters++
			}
			flush()
		}
	}
	for script, item := range evidence {
		if item.letters < 8 {
			continue
		}
		strong := item.letters >= 12 || item.letters*8 >= totalLetters
		switch script {
		case unicode.Hiragana, unicode.Katakana, unicode.Thai, unicode.Lao, unicode.Khmer, unicode.Myanmar:
			if item.letters >= 12 || (item.letters >= 8 && item.letters*8 >= totalLetters) {
				return true
			}
		case unicode.Hangul:
			if item.words >= 2 || item.letters >= 12 {
				return true
			}
		case unicode.Greek:
			if item.words >= 3 && strong {
				return true
			}
		default:
			if item.words >= 3 && strong {
				return true
			}
		}
	}
	return false
}

func foreignScript(r rune) *unicode.RangeTable {
	switch {
	case unicode.Is(unicode.Cyrillic, r):
		return unicode.Cyrillic
	case unicode.Is(unicode.Arabic, r):
		return unicode.Arabic
	case unicode.Is(unicode.Devanagari, r):
		return unicode.Devanagari
	case unicode.Is(unicode.Hebrew, r):
		return unicode.Hebrew
	case unicode.Is(unicode.Greek, r):
		return unicode.Greek
	case unicode.Is(unicode.Hiragana, r):
		return unicode.Hiragana
	case unicode.Is(unicode.Katakana, r):
		return unicode.Katakana
	case unicode.Is(unicode.Hangul, r):
		return unicode.Hangul
	case unicode.Is(unicode.Thai, r):
		return unicode.Thai
	case unicode.Is(unicode.Bengali, r):
		return unicode.Bengali
	case unicode.Is(unicode.Georgian, r):
		return unicode.Georgian
	case unicode.Is(unicode.Armenian, r):
		return unicode.Armenian
	case unicode.Is(unicode.Ethiopic, r):
		return unicode.Ethiopic
	case unicode.Is(unicode.Gujarati, r):
		return unicode.Gujarati
	case unicode.Is(unicode.Gurmukhi, r):
		return unicode.Gurmukhi
	case unicode.Is(unicode.Kannada, r):
		return unicode.Kannada
	case unicode.Is(unicode.Tamil, r):
		return unicode.Tamil
	case unicode.Is(unicode.Telugu, r):
		return unicode.Telugu
	case unicode.Is(unicode.Malayalam, r):
		return unicode.Malayalam
	case unicode.Is(unicode.Oriya, r):
		return unicode.Oriya
	case unicode.Is(unicode.Myanmar, r):
		return unicode.Myanmar
	case unicode.Is(unicode.Sinhala, r):
		return unicode.Sinhala
	case unicode.Is(unicode.Khmer, r):
		return unicode.Khmer
	case unicode.Is(unicode.Lao, r):
		return unicode.Lao
	case unicode.Is(unicode.Tibetan, r):
		return unicode.Tibetan
	case unicode.Is(unicode.Syriac, r):
		return unicode.Syriac
	case unicode.Is(unicode.Thaana, r):
		return unicode.Thaana
	case unicode.Is(unicode.Cherokee, r):
		return unicode.Cherokee
	case unicode.Is(unicode.Canadian_Aboriginal, r):
		return unicode.Canadian_Aboriginal
	case unicode.Is(unicode.Mongolian, r):
		return unicode.Mongolian
	default:
		return nil
	}
}
