package utils

import (
	"errors"
	"sync"
)

type Pool struct {
	uplimit  int
	valMap   map[interface{}]int
	delMap   map[interface{}]int
	New      func() (interface{}, error)
	getMutex sync.Mutex
}

func NewPool(uplimit int, f func() (interface{}, error)) *Pool {
	if uplimit < 1 {
		uplimit = 1
	}
	return &Pool{uplimit: uplimit, New: f, valMap: make(map[interface{}]int), delMap: make(map[interface{}]int)}
}

func (p *Pool) Get(reuse bool) (interface{}, error) {
	if !reuse {
		return p.New()
	}

	p.getMutex.Lock()
	defer p.getMutex.Unlock()

	//create x if the value map is empty
	if p.valMap == nil || len(p.valMap) == 0 {
		x, err := p.New()
		if err != nil {
			return nil, err
		}
		if p.uplimit > 1 {
			p.valMap[x] = p.uplimit - 1
		}
		return x, nil
	}

	//get one from the map
	for x, n := range p.valMap {
		n--
		if n < 1 {
			delete(p.valMap, x)
		} else {
			p.valMap[x] = n
		}
		return x, nil
	}
	return nil, errors.New("Unknown errors!")
}

//the 1st ret val check the frist time delpart
//the 2nd ret val check all clean from delMap
func (p *Pool) DelPart(x interface{}) (bool, bool) {
	p.getMutex.Lock()
	defer p.getMutex.Unlock()
	if ok, del := p.checkDel(x); ok {
		return false, del
	}
	p.delMap[x] = p.valMap[x] + 1
	delete(p.valMap, x)
	return true, false
}

//the first return value is check if the x is in the delMap
//the second return value is check if the x is clean from the delMap
func (p *Pool) checkDel(x interface{}) (bool, bool) {
	if val, ok := p.delMap[x]; ok {
		val++
		if val >= p.uplimit {
			delete(p.delMap, x)
			return true, true
		}
		p.delMap[x] = val
		return true, false
	}
	return false, false
}

func (p *Pool) Put(x interface{}) {
	p.getMutex.Lock()
	defer p.getMutex.Unlock()

	if ok, _ := p.checkDel(x); ok {
		return
	}

	//Put in the valMap
	n, ok := p.valMap[x]
	if ok {
		n++
		p.valMap[x] = n
	} else {
		p.valMap[x] = 1
	}
}
