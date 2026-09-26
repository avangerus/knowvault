package questions

import "fmt"

// instancePortOffset is the host-port distance between two question-set
// instances. Container names and volumes take the instance number as a suffix.
const instancePortOffset = 10

// ApplyInstance makes every resource a question-set run creates distinct per
// instance, so two runs with different KNOWVAULT_QUESTION_SET_INSTANCE values
// never share, reuse or remove each other's containers, host ports or volumes.
// Instance numbers are 1..9; a non-positive instance is the default single run
// and leaves the set exactly as the data file describes it.
//
// The containers, ports and volumes the set already used keep the scheme they
// had (suffix "-N", host port + 10*N). The unconfirmed database H5 asks about —
// which used to keep its fixed container name and host port in every instance,
// so one run could remove or reuse the other's database — now follows the same
// scheme, and its data volume is named and per-instance instead of anonymous.
func (set *Set) ApplyInstance(instance int) {
	if instance <= 0 {
		return
	}
	suffix := fmt.Sprintf("-%d", instance)
	offset := instancePortOffset * instance
	set.Environment.ProductContainer += suffix
	set.Environment.SourceContainer += suffix
	set.Environment.ProductPort += offset
	set.Environment.SourcePort += offset
	set.Environment.UnconfirmedDatabase.Container += suffix
	set.Environment.UnconfirmedDatabase.Port += offset
	set.Environment.UnconfirmedDatabase.Volume += suffix
}
