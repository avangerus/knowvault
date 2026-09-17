package operator

// migrationChecksumMatches preserves exact equality and admits only the six
// owner-approved comment translations below. Compatibility is directional:
// an exact legacy ledger entry may accompany the exact translated file.
// Recorded checksums are never rewritten, and no SQL is reapplied.
func migrationChecksumMatches(name, recorded, actual string) bool {
	if recorded == actual {
		return true
	}
	switch name {
	case "000077_stage2_evidence_fragment_readable_per_scope.sql":
		return recorded == "83ce299c009c877b379f436272dd62780306e659d806d2e62f004387c3055779" &&
			actual == "e7706f35480571675c537821b1640e712b12333c79f15b395ccc1fbb2bfa681c"
	case "000078_stage3_governed_query_workspace_binding.sql":
		return recorded == "eeb5f884582201564fda16a5fbd66791ce1b3db81ea3b72de8f789be3234eb45" &&
			actual == "a7a988e1b492622c98e604fc4ff3eb9fc682cd3cea7760c268a4c3cbfe096ade"
	case "000080_stage3_conversation_continuation_revision_tolerant.sql":
		return recorded == "60c1745f0274638c97d090a220ede58f26d8dc8292f32d14cd58fd988a5aee27" &&
			actual == "8eed587de6da613698860d0072f9bcb3a963dcffc2c653e3bb0f64097c2267cd"
	case "000082_stage3_structured_snapshot_status_role.sql":
		return recorded == "37dc121288e5a3ed63b61bb4a26d3bbec8bf1e6687e68ff1129abb811ed935f6" &&
			actual == "8d5ea8f86a88ec814fa30d3d9b3bce383c54dc5a9b3df1cc718866348578d408"
	case "000083_stage3_structured_source_scope_names.sql":
		return recorded == "7456d5908c9356f471c0a465fd1f68041251333c5d8e9ffbcf2dc12ea6853672" &&
			actual == "369bb4184bc418040310841979d54b2533f788e05bd5fc4011e38ec3c4a25545"
	case "000094_stage3_metric_definitions.sql":
		return recorded == "fc4927677050e97753598fe04a580c49f97d57b4780551621557c7bcc1c3e6c8" &&
			actual == "9de3a3797bfcfcb99f500cc67b64f29d1d5285389cbf0c8541c5b03cb307d440"
	default:
		return false
	}
}
