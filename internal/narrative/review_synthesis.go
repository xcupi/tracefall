package narrative

import (
	"fmt"
	"sort"
	"strings"
)

// PrepareReviewSynthesis uses only validated, locally restored commentary and
// original primary excerpts. It rebuilds one new pseudonym/citation namespace;
// neither batch-local aliases nor raw model output are carried forward.
func PrepareReviewSynthesis(in ReviewInput, commentary []Sentence) (*ReviewPrepared, int, error) {
	names := in.Names
	for pass := 0; pass < maxPasses; pass++ {
		in.Names = names
		p, err := PrepareReview(in)
		if err != nil {
			return nil, len(commentary), err
		}
		aliases := map[Cite]string{}
		for a, c := range p.reviewRefs {
			aliases[c] = a
		}
		p.System += "\nSYNTHESIS: compare only the validated commentary with the primary excerpts. Commentary is not evidence. Preserve each item's kind, disagreements, uncertainty and original primary citations. Never promote a hypothesis or possible_conflict into an established observation; unclassified is an abstention, not an observation. Do not automatically reconcile conflicting detector claims. Do not infer agreement or identity from prior packet-local pseudonyms. Do not claim global, raw-image, or whole-case coverage."
		p.User += "\nVALIDATED COMMENTARY (not primary evidence):\n"
		omitted := 0
		var omittedIndices []int
		for index, sentence := range commentary {
			var refs []string
			valid := true
			primary := false
			for _, c := range sentence.Cites {
				a, ok := aliases[c]
				if !ok {
					valid = false
					break
				}
				refs = append(refs, a)
				if c.Kind == "enrichment" {
					// An external opinion can anchor commentary only while its
					// verified original event excerpts are in this new packet.
					for _, v := range p.FrozenVT {
						if v.ID == c.ID && len(v.SourceEventIDs) > 0 {
							primary = true
						}
					}
				}
				if c.Kind == "event" || c.Kind == "finding" || c.Kind == "correlation" {
					primary = true
				}
			}
			if !valid || !primary {
				omitted++
				omittedIndices = append(omittedIndices, index)
				continue
			}
			sort.Strings(refs)
			text := p.text(sentence.Text, DefaultLimits.MaxSentenceRunes)
			kind := sentence.Kind
			if !knownReviewKind(kind) {
				// Historical/malformed metadata must not become prompt prose.
				kind = "unclassified"
			}
			line := fmt.Sprintf("commentary_only | kind=%s | %s [%s]\n", kind, text, strings.Join(refs, ", "))
			// Reserve room for catalog/omission counts after preparation.
			if len(p.System)+len(p.User)+len(line) > ReviewMaxBytes-4096 {
				omitted++
				omittedIndices = append(omittedIndices, index)
				continue
			}
			p.User += line
		}
		if len(p.leaks) > 0 {
			return nil, len(commentary), ErrLeak
		}
		more := newNames(p.Entities(), names)
		if len(more.Hosts)+len(more.Users)+len(more.Domains) > 0 {
			names.Hosts = append(names.Hosts, more.Hosts...)
			names.Users = append(names.Users, more.Users...)
			names.Domains = append(names.Domains, more.Domains...)
			continue
		}
		for _, d := range digitsRe.FindAllString(p.User, -1) {
			p.numbers[trimZeros(d)] = true
		}
		p.Privacy.PayloadBytes = len(p.System) + len(p.User)
		p.SynthesisOmittedIndices = omittedIndices
		return p, omitted, nil
	}
	return nil, len(commentary), ErrLeak
}
