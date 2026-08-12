package queue

const (
	metaName       = "meta.json"
	bodyName       = "message.eml"
	addStateName   = "add.state"
	reviveMetaName = "revive.json"

	// Equal-length states allow the acceptance transition to update the
	// already-durable marker in place without another directory mutation.
	addPending  = "outboxd-add-v1:pending \n"
	addAccepted = "outboxd-add-v1:accepted\n"

	dirReady   = "ready"
	dirDead    = "dead"
	dirTmp     = "tmp"
	dirDSN     = "dsn"
	dirCorrupt = "corrupt"
	dirTrash   = "trash"

	maxAddStateBytes = 64
)
