package config

import "time"

const (
	defaultConfigName        = "config.yml"
	DataMemoryBudget         = int64(512 << 20)
	DataMemoryCopies         = int64(8)
	DataMemoryOverhead       = int64(1<<20) + 1000*128
	MaxDataWorkers           = 8
	MaxMessageBytes          = (DataMemoryBudget - DataMemoryOverhead) / DataMemoryCopies
	MaxRecipients            = 1000
	MaxMessagesPerHour       = 1_000_000
	MaxRecipientsPerHour     = 10_000_000
	MaxMessageBurst          = MaxMessagesPerHour
	MaxRecipientBurst        = MaxRecipientsPerHour
	MaxDeliveryAttempts      = 100
	MaxDomainConcurrency     = 64
	MaxGlobalConcurrency     = 256
	MaxUserConcurrency       = 64
	MaxMXCandidates          = 100
	MaxIPCandidatesPerMX     = 64
	MaxConnections           = 3840
	MaxConnectionsPerIP      = 256
	MaxReplyConnections      = 1024
	MaxReplyConnectionsPerIP = 64
	MaxAuthWorkers           = 8
	MaxOpenPGPIdentities     = 1000
	MaxOpenPGPRecipientKeys  = 1000
	SPFDNSLookupLimit        = 10

	MaxSMTPReadTimeout           = 30 * time.Minute
	MaxSMTPWriteTimeout          = 30 * time.Minute
	MaxReplyReadTimeout          = 5 * time.Minute
	MaxReplyWriteTimeout         = 5 * time.Minute
	MaxDeadRetention             = 365 * 24 * time.Hour
	MaxCorruptRetention          = 365 * 24 * time.Hour
	MaxDeliveryLifetime          = 30 * 24 * time.Hour
	MaxInitialRetryDelay         = 24 * time.Hour
	MaxRetryDelay                = 7 * 24 * time.Hour
	MaxDeliveryDNSTimeout        = 2 * time.Minute
	MaxDeliveryAttemptTimeout    = time.Hour
	MaxDeliveryConnectionTimeout = 2 * time.Minute
	MaxDeliveryCommandTimeout    = 10 * time.Minute
	MaxDeliverySubmissionTimeout = 30 * time.Minute

	// EnvConfigPath overrides the config file path.
	EnvConfigPath = "OUTBOXD_CONFIG"
)
