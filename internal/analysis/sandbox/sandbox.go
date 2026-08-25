package sandbox

type Sandbox interface {
	Create() error
	CopySample(samplePath string) error
	Execute() error
	Collect() (string, error)
	Destroy() error
}