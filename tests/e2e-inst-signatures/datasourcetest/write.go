package datasourcetest

import (
	"encoding/json"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/aquasecurity/tracee/types/detect"
)

type e2eWritable struct {
	cache *lru.Cache[string, string]
}

func New() detect.DataSource {
	cache, _ := lru.New[string, string](1024)
	return &e2eWritable{
		cache,
	}
}

func (ctx *e2eWritable) Get(key interface{}) (map[string]interface{}, error) {
	val, ok := key.(string)
	if !ok {
		return nil, detect.ErrKeyNotSupported
	}

	res, ok := ctx.cache.Get(val)
	if !ok {
		return nil, detect.ErrDataNotFound
	}

	return map[string]interface{}{
		"value": res,
	}, nil
}

func (ctx *e2eWritable) Version() uint {
	return 1
}

func (ctx *e2eWritable) Keys() []string {
	return []string{"string"}
}

func (ctx *e2eWritable) Schema() string {
	schema := map[string]interface{}{
		"value": "string",
	}

	s, _ := json.Marshal(schema)
	return string(s)
}

func (ctx *e2eWritable) Namespace() string {
	return "e2e_inst"
}

func (ctx *e2eWritable) ID() string {
	return "demo"
}

func (ctx *e2eWritable) Write(data map[interface{}]interface{}) error {
	for key, val := range data {
		err := ctx.writeDataEntry(key, val)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ctx *e2eWritable) writeDataEntry(key, value any) error {
	keyStr, ok := key.(string)
	if !ok {
		return detect.ErrFailedToUnmarshal
	}

	valueStr, ok := value.(string)
	if !ok {
		return detect.ErrFailedToUnmarshal
	}

	ctx.cache.Add(keyStr, valueStr)
	return nil
}

func (ctx *e2eWritable) Values() []string {
	return []string{"string"}
}
