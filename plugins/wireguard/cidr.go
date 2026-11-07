package wireguard

import (
	"fmt"
	"net/netip"
)

// SubtractPrefixes returns include minus exclude as a list of CIDR prefixes.
// Families are handled independently; empty exclude leaves include unchanged.
func SubtractPrefixes(include, exclude []netip.Prefix) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(include))
	for _, in := range include {
		result = append(result, in.Masked())
	}
	for _, ex := range exclude {
		ex = ex.Masked()
		next := make([]netip.Prefix, 0, len(result)*2)
		for _, in := range result {
			next = append(next, subtractOne(in, ex)...)
		}
		result = next
	}
	return result
}

func subtractOne(base, remove netip.Prefix) []netip.Prefix {
	base = base.Masked()
	remove = remove.Masked()
	if base.Addr().BitLen() != remove.Addr().BitLen() {
		return []netip.Prefix{base}
	}
	if !base.Overlaps(remove) {
		return []netip.Prefix{base}
	}
	// remove fully covers base
	if remove.Bits() <= base.Bits() && remove.Contains(base.Addr()) {
		return nil
	}

	var out []netip.Prefix
	stack := []netip.Prefix{base}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		cur = cur.Masked()
		if !cur.Overlaps(remove) {
			out = append(out, cur)
			continue
		}
		if remove.Bits() <= cur.Bits() && remove.Contains(cur.Addr()) {
			continue
		}
		left, right, ok := splitPrefix(cur)
		if !ok {
			continue
		}
		stack = append(stack, right, left)
	}
	return out
}

func splitPrefix(p netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	bits := p.Bits()
	maxBits := p.Addr().BitLen()
	if bits >= maxBits {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	left, err := p.Addr().Prefix(bits + 1)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, false
	}

	var raw []byte
	if p.Addr().Is4() {
		a4 := p.Addr().As4()
		raw = append([]byte(nil), a4[:]...)
	} else {
		a16 := p.Addr().As16()
		raw = append([]byte(nil), a16[:]...)
	}
	byteIdx := bits / 8
	bitIdx := 7 - (bits % 8)
	raw[byteIdx] |= 1 << uint(bitIdx)

	var sibling netip.Addr
	if p.Addr().Is4() {
		var a4 [4]byte
		copy(a4[:], raw)
		sibling = netip.AddrFrom4(a4)
	} else {
		var a16 [16]byte
		copy(a16[:], raw)
		sibling = netip.AddrFrom16(a16)
	}
	right, err := sibling.Prefix(bits + 1)
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	return left, right, true
}

func parsePrefixList(raw string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0)
	for _, part := range splitList(raw) {
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("%q ist kein Netz", part)
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}

// ApplyExcludedIPs validates include/exclude CIDRs and returns the computed
// AllowedIPs strings plus the normalised exclude list (may be empty).
func ApplyExcludedIPs(allowedRaw, excludedRaw string) (allowed []string, excluded []string, err error) {
	include, err := parsePrefixList(allowedRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("AllowedIPs: %w", err)
	}
	if len(include) == 0 {
		return nil, nil, fmt.Errorf("AllowedIPs darf nicht leer sein")
	}
	exclude, err := parsePrefixList(excludedRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("ExcludedIPs: %w", err)
	}
	final := SubtractPrefixes(include, exclude)
	if len(final) == 0 {
		return nil, nil, fmt.Errorf("ExcludedIPs entfernen alle AllowedIPs")
	}
	allowed = make([]string, 0, len(final))
	for _, p := range final {
		allowed = append(allowed, p.String())
	}
	excluded = make([]string, 0, len(exclude))
	for _, p := range exclude {
		excluded = append(excluded, p.String())
	}
	return allowed, excluded, nil
}
