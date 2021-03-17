CFLAGS=-O3 -Wpedantic `pkg-config --libs --cflags glib-2.0 libalpm libalpm_octopi_utils libcurl yajl`

avg-audit: avg-audit.c
	gcc $(CFLAGS) -o $@ $<

avg-audit.c:
	wget -O avg-audit.c -q --show-progress -N https://raw.githubusercontent.com/644/avg-audit/master/avg-audit.c

shell:
	wget -O avg-audit -q --show-progress -N https://raw.githubusercontent.com/644/avg-audit/master/avg-audit

install:
	install -m 0755 avg-audit /usr/local/bin/

clean:
	rm -f /usr/local/bin/avg-audit
