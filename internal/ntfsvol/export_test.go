package ntfsvol

// mftByteOffsetForTest maps a record number to its byte offset in the
// volume, so tests can damage a specific record.
func (v *Volume) mftByteOffsetForTest(rec uint64) int64 {
	cs := int64(v.cluster)
	pos := int64(rec) * int64(v.recordSize)
	for _, r := range v.mft.runs {
		if pos >= r.vcn*cs && pos < (r.vcn+r.length)*cs {
			return r.lcn*cs + (pos - r.vcn*cs)
		}
	}
	return -1
}
