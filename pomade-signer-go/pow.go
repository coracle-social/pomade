package main

func getPow(id [32]byte) uint32 {
	var count uint32
	for _, b := range id {
		if b == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (b>>i)&1 == 0 {
				count++
				continue
			}
			return count
		}
	}
	return count
}
