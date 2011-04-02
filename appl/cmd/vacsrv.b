implement Vacsrv;

include "sys.m";
	sys: Sys;
	sprint: import sys;
include "draw.m";
include "arg.m";
include "dial.m";
	dial: Dial;
include "string.m";
	str: String;
include "styx.m";
	styx: Styx;
	Tmsg, Rmsg: import styx;
include "keyring.m";
	kr: Keyring;
include "tables.m";
	tables: Tables;
	Table, Strhash: import tables;
include "venti.m";
	venti: Venti;
	Vmsg, Entry, Score, Session: import venti;
include "vac.m";
	vac: Vac;
	Direntry, Metablock, Metaentry: import vac;

Vacsrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

dflag: int;
addr := "$venti";
nflag: int;
pflag: int;
sflag: int;
tflag: int;
Vflag: int;
mtpt: string;

RC: type chan of (array of byte, string);
vreqc: chan of (int, Score, int, RC);

zeroscore: Score;
root: ref V;
msize: int;

Enowrite:	con "no writes allowed";
Ebadfid:	con "bad fid";
Efidinuse:	con "fid in use";
Efidopen:	con "fid already open";
Efidnotopen:	con "fid not open";
Eperm:		con "permission denied";
Enotfound:	con "file not found";
Ediroffset:	con "bad directory offset";
Esmalldirread:	con "small directory read";

Fid: adt {
	open:	int;
	d:	ref D;
	v:	ref V;
};

# directory open for reading
D: adt {
	dirlock:	chan of int;
	off:	big;
	i:	int;
	b:	int;
	mb:	ref Metablock;
	me:	int;
	buf:	array of byte;
};


# everything vac about a file
V: adt {
	d:	ref Direntry;
	t:	ref Hashtree;	# data (entries for dir)
	mt:	ref Hashtree;	# only for dir, metablocks with direntries
	p:	ref V;		# parent
	path:	string;

	mk:	fn(d: ref Direntry, e, me: ref Entry, p: ref V): ref V;
};

# venti block cache entry
C: adt {
	b:	int;		# block number, used if >= 0 (only for non-ptr blocks)
	s:	Score;
	d:	array of byte;
};

Hashtree: adt {
	e:	ref Entry;

	cachelock:	chan of int;
	cache:	array of (C, C);  # .t0 is most recently used, indexed by depth

	mk:	fn(e: ref Entry): ref Hashtree;
	get:	fn(t: self ref Hashtree, b: int): (array of byte, string);
};

init(nil: ref Draw->Context, args: list of string)
{
	sys = load Sys Sys->PATH;
	arg := load Arg Arg->PATH;
	dial = load Dial Dial->PATH;
	str = load String String->PATH;
	styx = load Styx Styx->PATH;
	styx->init();
	kr = load Keyring Keyring->PATH;
	tables = load Tables Tables->PATH;
	venti = load Venti Venti->PATH;
	vac = load Vac Vac->PATH;
	venti->init();
	vac->init();

	sys->pctl(Sys->NEWPGRP, nil);

	arg->init(args);
	arg->setusage(arg->progname()+" [-dnpstV] [-a addr] [-m mtpt] score");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		'a' =>	addr = arg->earg();
		'm' =>	mtpt = arg->earg();
		'n' =>	nflag++;
		'p' =>	pflag++;
		't' =>	tflag++;
		's' =>	sflag++;
		'V' =>	Vflag++;
		* =>	arg->usage();
		}
	args = arg->argv();
	if(len args != 1)
		arg->usage();
	(ok, s) := Score.parse(hd args);
	if(ok < 0)
		fail(sprint("bad score: %r"));

	zeroscore = Score.zero();
	lookinit();

	addr = dial->netmkaddr(addr, "net", "venti");
	cc := dial->dial(addr, nil);
	if(cc == nil)
		fail(sprint("dial: %r"));
	vfd := cc.dfd;
	ss := Session.new(vfd);
	if(ss == nil)
		fail(sprint("handshake: %r"));

	vreqc = chan of (int, Score, int, RC);
	spawn ventisrv(vfd);

	dr := vread(s, venti->Roottype, venti->Rootsize);
	if(dr == nil)
		fail(sprint("reading root score: %r"));
	r := venti->unpackroot(dr);
	if(r == nil)
		fail(sprint("parsing root score: %r"));
	if(dflag) warn("have root");

	td := vread(r.score, venti->Dirtype, 3*venti->Entrysize);
	if(td == nil)
		fail(sprint("reading root directory: %r"));
	top := array[3] of ref Entry;
	for(i := 0; i < len top; i++) {
		e := venti->unpackentry(td[i*venti->Entrysize:(i+1)*venti->Entrysize]);
		if(e == nil)
			fail(sprint("root dir entry: %r"));
		top[i] = e;
	}
	if(dflag) warn("have root entries");

	spawn readentry(top[0]);
	spawn readentry(top[1]);

	rd := vread(top[2].score, venti->Datatype, 8*1024);
	if(rd == nil)
		fail(sprint("reading root entry: %r"));
	mb := Metablock.unpack(rd);
	if(mb == nil)
		fail(sprint("parsing root metablock: %r"));
	rme := Metaentry.unpack(rd, 0);
	if(rme == nil)
		fail(sprint("parsing root metaentry: %r"));
	rootde := Direntry.unpack(rd[rme.offset:rme.offset+rme.size]);
	if(rootde == nil)
		fail(sprint("parsing root direntry: %r"));
	root = V.mk(rootde, top[0], top[1], nil);
	if(dflag) warn("have root entry");

	if(mtpt == nil)
		return main(sys->fildes(0));

	if(sys->pipe(fds := array[2] of ref Sys->FD) < 0)
		fail(sprint("pipe: %r"));
	spawn main(fds[0]);
	if(nflag)
		sys->pctl(sys->NEWNS, nil);
	if(sys->mount(fds[1], nil, mtpt, Sys->MREPL, nil) < 0)
		fail(sprint("mount: %r"));
}

readentry(e: ref Entry)
{
	nb := int ((e.size+big e.dsize-big 1)/big e.dsize);
	t := Hashtree.mk(e);
	for(i := 0; i < nb; i++) 
		t.get(i);
}

R: adt {
	t:	int;
	s:	Score;
	nmax:	int;
	rc:	RC;
};

Link: adt[T] {
	e:	T;
	next:	cyclic ref Link[T];
};

ventisrv(fd: ref Sys->FD)
{
	tmc := chan[256] of ref Vmsg;
	rmc := chan[1] of ref Vmsg;
	errc := chan of string;
	spawn vreader(fd, rmc, errc);
	spawn vwriter(fd, tmc, errc);

	tidtab := Table[ref R].new(13, nil);

	first,
	last: ref Link[ref R];

	tids: list of int;
	for(i := 0; i < 256; i++)
		tids = i::tids;

	for(;;)
	alt {
	e := <-errc =>
		fail("venti: "+e);

	mm := <-rmc =>
		r := tidtab.find(mm.tid);
		if(r == nil) {
			warn("bogus tid from server");
			continue;
		}
		tidtab.del(mm.tid);
		tids = mm.tid::tids;
		pick m := mm {
		Rerror =>
			r.rc <-= (nil, m.e);
		Rread =>
			r.rc <-= (m.data, nil);
		* =>
			warn("bogus message from server");
		}

		if(first != nil) {
			tid := hd tids;
			tids = tl tids;
			r = first.e;
			tidtab.add(tid, r);
			first = first.next;
			if(first == nil)
				last = nil;
			tmc <-= ref Vmsg.Tread(1, tid, r.s, r.t, r.nmax);
		}

	(t, s, n, rc) := <-vreqc =>
		r := ref R(t, s, n, rc);
		if(tids != nil) {
			tid := hd tids;
			tids = tl tids;
			tidtab.add(tid, r);
			tmc <-= ref Vmsg.Tread(1, tid, s, t, n);
		} else {
			l := ref Link[ref R](r, nil);
			if(last != nil)
				last.next = l;
			else
				first = l;
			last = l;
		}
	}
}

vreader(fd: ref Sys->FD, c: chan of ref Vmsg, errc: chan of string)
{
	for(;;) {
		(m, err) := Vmsg.read(fd);
		if(err != nil) {
			errc <-= "read: "+err;
			return;
		}
		if(tflag) warn("v <- "+m.text());
		c <-= m;
	}
}

vwriter(fd: ref Sys->FD, c: chan of ref Vmsg, errc: chan of string)
{
	for(;;) {
		mm := <-c;
		if(tflag) warn("v -> "+mm.text());
		if(pflag)
		pick m := mm {
		Tread =>
			if(sys->print("%d %s\n", m.etype, m.score.text()) < 0)
				errc <-= sprint("write: %r");
		}
		if(sys->write(fd, d := mm.pack(), len d) != len d)
			errc <-= sprint("write: %r");
	}
}

# work
W: adt {
	flushed: 	int;
	newfid:		int;		# valid if >= 0
	nf:		ref Fid;	# may be nil, even with newfid >= 0
	m:		ref Tmsg;
	rm:		ref Rmsg;
	err:		string;
};

main(sfd: ref Sys->FD)
{
	stc := chan[1] of ref Tmsg;
	src := chan[1] of ref Rmsg;
	serrc := chan of string;

	msize = 8*1024;
	okversion := 0;
	spawn styxread(sfd, stc, serrc);
	spawn styxwrite(sfd, src, serrc);

	fids := Table[ref Fid].new(31, nil);
	newfids := Table[ref W].new(11, nil);
	tags := Table[ref W].new(11, nil);
	rc := chan[1] of ref W;

	for(;;)
	alt {
	e := <-serrc =>
		if(e == nil) {
			killgrp(pid());
			return;
		}
		fail("styx: "+e);

	tm := <-stc =>
		if(!okversion)
			pick m := tm {
			Readerror =>	{}
			Version =>	{}
			* =>
				fail("9p message while no 9p version negotiated");
			}

		pick m := tm {
		Readerror =>
			fail("9P read error: "+m.error);
		Version =>
			fids = fids.new(31, nil);
			rm := ref Rmsg.Version(m.tag, m.msize, "unknown");
			okversion = 0;
			if(is9p2000(m.version)) {
				rm.version = "9P2000";
				msize = m.msize;
				okversion = 1;
			}
			src <-= rm;
		Attach =>
			if(m.afid != styx->NOFID)
				src <-= ref Rmsg.Error(m.tag, "no auth");
			else if(fids.find(m.fid) != nil)
				src <-= ref Rmsg.Error(m.tag, Efidinuse);
			else {
				src <-= ref Rmsg.Attach(m.tag, qid(root.d));
				f := ref Fid(0, nil, root);
				fids.add(m.fid, f);
			}
		Flush =>
			w := tags.find(m.oldtag);
			if(w != nil) {
				w.flushed = 1;
				if(w.newfid >= 0) {
					newfids.del(w.newfid);
					w.newfid = -1;
				}
				tags.del(m.oldtag);
			}
			src <-= ref Rmsg.Flush(m.tag);
		Walk =>
			f := fids.find(m.fid);
			if(f != nil)
				if(dflag) warn(sprint("walk, fid: name %q, score %s", f.v.d.elem, f.v.t.e.score.text()));

			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else if(m.fid != m.newfid && (fids.find(m.newfid) != nil || newfids.find(m.newfid) != nil))
				src <-= ref Rmsg.Error(m.tag, Efidinuse);
			else if(f.open)
				src <-= ref Rmsg.Error(m.tag, Efidopen);
			else if(len m.names == 0) {
				nf := ref Fid(0, nil, f.v);
				if(m.fid != m.newfid)
					fids.add(m.newfid, nf);
				src <-= ref Rmsg.Walk(m.tag, array[0] of sys->Qid);
			} else if(badname(m.names)) {
				src <-= ref Rmsg.Error(m.tag, "bad name");
			} else {
				w := ref W(0, m.newfid, nil, tm, nil, nil);
				tags.add(m.tag, w);
				newfids.add(m.newfid, w);
				spawn twalk(w, m, f, rc);
			}
		Open =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else if(m.mode != styx->OREAD)
				src <-= ref Rmsg.Error(m.tag, Eperm);
			else if(f.open)
				src <-= ref Rmsg.Error(m.tag, Efidopen);
			else {
				f.open++;
				src <-= ref Rmsg.Open(m.tag, qid(f.v.d), msize-24);
			}
		Read =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else if(!f.open)
				src <-= ref Rmsg.Error(m.tag, Efidnotopen);
			else {
				w := ref W(0, -1, nil, tm, nil, nil);
				tags.add(m.tag, w);
				if(f.v.t.e.flags&venti->Entrydir)
					spawn treaddir(w, m, f, m.offset, min(msize-24, m.count), rc);
				else
					spawn tread(w, m, f, m.offset, min(msize-24, m.count), rc);
			}
		Clunk or
		Remove =>
			f := fids.find(m.fid);
			fids.del(m.fid);
			if(f == nil) {
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
				continue;
			}

			if(tagof m == tagof Tmsg.Clunk)
				src <-= ref Rmsg.Clunk(m.tag);
			else
				src <-= ref Rmsg.Error(m.tag, Enowrite);
		Stat =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else
				src <-= ref Rmsg.Stat(m.tag, stat(f.v));

		Auth =>
			src <-= ref Rmsg.Error(m.tag, "no auth");
		Create =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		Write =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		Wstat =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		}

	w := <-rc =>
		if(w.flushed)
			continue;
		tags.del(w.m.tag);
		if(w.newfid >= 0)
			newfids.del(w.newfid);

		if(w.err != nil) {
			src <-= ref Rmsg.Error(w.m.tag, w.err);
			continue;
		}
		if(w.rm == nil)
			raise "rmsg not set after work?";
		if(w.newfid >= 0 && w.nf != nil)
			fids.add(w.newfid, w.nf);
		src <-= w.rm;
	}
}

is9p2000(s: string): int
{
	(v, nil) := str->splitstrl(s, ".");
	if(str->prefix("9P", v))
	if(len v == len "9Pnnnn")
	if(((vers, nil) := str->toint(v[2:], 10)).t1 == nil)
	if(vers >= 2000)
		return 1;
	return 0;
}

slash(s: string): int
{
	for(i := 0; i < len s; i++)
		if(s[i] == '/')
			return 1;
	return 0;
}

badname(n: array of string): int
{
	for(i := 0; i < len n; i++)
		if((e := n[i]) == "." || slash(e))
			return 1;
	return 0;
}

twalk(w: ref W, m: ref Tmsg.Walk, f: ref Fid, rc: chan of ref W)
{
	qids := array[len m.names] of sys->Qid;
	v := f.v;
	for(i := 0; i < len m.names; i++) {
		nv: ref V;
		(nv, w.err) = walk(v, m.names[i]);
		if(nv == nil)
			break;
		v = nv;
		qids[i] = sys->Qid(v.d.qid, v.d.mcount, (v.d.emode>>24)&16rff);
	}
	if(i != 0) {
		w.err = nil;
		w.rm = ref Rmsg.Walk(m.tag, qids[:i]);
		if(i == len m.names)
			w.nf = ref Fid(0, nil, v);
	}
	rc <-= w;
}

treaddir(w: ref W, m: ref Tmsg.Read, f: ref Fid, off: big, n: int, rc: chan of ref W)
{
	if(f.d == nil || f.d.off == big 0) {
		dirlock := chan[1] of int;
		dirlock <-= 1;
		f.d = ref D(dirlock, big 0, 0, 0, nil, 0, nil);
	}
	<-f.d.dirlock;
	d: array of byte;
	(d, w.err) = readdir(f, off, n);
	f.d.dirlock <-= 1;
	if(w.err == nil)
		w.rm = ref Rmsg.Read(m.tag, d);
	rc <-= w;
}

tread(w: ref W, m: ref Tmsg.Read, f: ref Fid, off: big, n: int, rc: chan of ref W)
{
	d: array of byte;
	(d, w.err) = read(f, off, n);
	if(w.err == nil)
		w.rm = ref Rmsg.Read(m.tag, d);
	rc <-= w;
}

V.mk(d: ref Direntry, e, me: ref Entry, p: ref V): ref V
{
	if(me != nil)
		mt := Hashtree.mk(me);
	if(p == nil)
		path := "";
	else
		path = p.path+"/"+d.elem;
	return ref V(d, Hashtree.mk(e), mt, p, path);
}

nocache := C(-2, Score(nil), nil);
Hashtree.mk(e: ref Entry): ref Hashtree
{
	nocache.s = zeroscore;
	lockc := chan[1] of int;
	lockc <-= 1;
	cache := array[e.depth+1] of {* => (nocache, nocache)};
	return ref Hashtree(e, lockc, cache);
}

# if b >= 0, look for that.  otherwise look at s.
cachelook(t: ref Hashtree, depth, b: int, s: Score): array of byte
{
	<-t.cachelock;
	(c0, c1) := t.cache[depth];
	d: array of byte;
	if(b >= 0 && c0.b == b || b < 0 && c0.s.eq(s))
		d = c0.d;
	else if(b >= 0 && c1.b == b || b < 0 && c1.s.eq(s)) {
		t.cache[depth] = (c1, c0);
		d = c1.d;
	}
	t.cachelock <-= 1;
	return d;
}

cacheput(t: ref Hashtree, depth, b: int, s: Score, d: array of byte)
{
	<-t.cachelock;
	if(t.cache[depth].t0.b == -2)
		t.cache[depth].t0 = t.cache[depth].t1;
	t.cache[depth].t1 = C(b, s, d);
	t.cachelock <-= 1;
}

tvread(t: ref Hashtree, depth, b, ty, sz: int, s: Score): array of byte
{
	d := cachelook(t, depth, b, s);
	if(d != nil)
		return d;

	return vread(s, ty, sz);
}

Hashtree.get(t: self ref Hashtree, b: int): (array of byte, string)
{
if(dflag) warn(sprint("t.get, b %d", b));
	s := t.e.score;

	cd := cachelook(t, t.e.depth, b, Score(nil));
	if(cd != nil)
		return (cd, nil);

	eb := int (t.e.size/big t.e.dsize);
	if(b > eb)
		raise "block not in tree";

	if(t.e.depth > 0) {
		pp := t.e.psize/venti->Scoresize;
		pt := pp**(t.e.depth-1);
		xb := b;
		for(i := 0; i < t.e.depth; i++) {
			d := tvread(t, i, -1, venti->Pointertype0+i, t.e.psize, s);
			if(d == nil)
				return (nil, sprint("venti read: %r"));
			cacheput(t, i, -1, s, d);
			p := xb/pt;
			o := p*venti->Scoresize;
			if(o >= len d) {
				# extend with zero scores, all the way to the data block
				s = zeroscore;
				break;
			}
			s = Score(d[o:o+venti->Scoresize]);
			xb %= pt;
			pt /= pp;
		}
	}

	dt := venti->Datatype;
	if(t.e.flags&venti->Entrydir)
		dt = venti->Dirtype;
	r := tvread(t, t.e.depth, b, dt, t.e.dsize, s);
	if(r == nil)
		return (nil, sprint("venti read: %r"));
	if(len r < t.e.dsize) {
		n := t.e.size-big b*big t.e.dsize;
		if(n > big t.e.dsize)
			n = big t.e.dsize;
		if(len r < int n) {
			nr := array[int n] of {* => byte 0};
			nr[:] = r;
			r = nr;
		}
	}
	cacheput(t, t.e.depth, b, s, r);
	return (r, nil);
}

vread(s: Score, t, nmax: int): array of byte
{
	if(zeroscore.eq(s))
		return array[0] of byte;

	vreqc <-= (t, s, nmax, rc := chan of (array of byte, string));
	(d, err) := <-rc;
	if(err == nil && Vflag && !s.eq(ns := Score(sha1(d))))
		err = sprint("bad data from venti server, requested %s, got %s", s.text(), ns.text());
	if(err == nil)
		return d;
	sys->werrstr(err);
	return nil;
}

getentry(v: ref V, i: int): (ref Entry, string)
{
if(dflag) warn(sprint("getentry, i %d", i));
	e := v.t.e;
	if(big (i+1)*big venti->Entrysize > e.size)
		return (nil, "entry outside file");
	bb := e.dsize/venti->Entrysize;
	b := i/bb;
	(d, err) := v.t.get(b);
	if(err != nil)
		return (nil, err);
	o := (i%bb)*venti->Entrysize;
	ne := venti->unpackentry(d[o:o+venti->Entrysize]);
	if(ne == nil)
		return (nil, sprint("%r"));
	return (ne, nil);
}

# we keep Nlookup paths in the cache for lookup.
# by keeping V alive, we keep the blocks in its hashtree(s) cached too.
# least recently used eviction scheme.
# lookfirst is lru, looklast is mru.
Nlookup: con 64;
E: adt {
	v:	ref V;
	prev,
	next:	cyclic ref E;
};
lookfirst,
looklast: ref E;
lookpaths: ref Strhash[ref E];
lookuplock: chan of int;

lookinit()
{
	lookpaths = Strhash[ref E].new(31, nil);

	lookuplock = chan[1] of int;
	lookuplock <-= 1;

	ee := array[Nlookup] of {* => ref E};
	for(i := 0; i < len ee; i++) {
		if(i-1 >= 0)
			ee[i].prev = ee[i-1];
		if(i+1 < len ee)
			ee[i].next = ee[i+1];
	}
	lookfirst = ee[0];
	looklast = ee[len ee-1];
}

looktake(e: ref E)
{
	if(e == lookfirst)
		lookfirst = lookfirst.next;
	else if(e == looklast)
		looklast = looklast.prev;
	else {
		e.prev.next = e.next;
		e.next.prev = e.prev;
	}
	lookfirst.prev = looklast.next = nil;
	e.prev = e.next = nil;
}

lookup(path: string): (int, ref V)
{
	<-lookuplock;
	(ok, nv) := lookup0(path);
	lookuplock <-= 1;
	return (ok, nv);
}

lookup0(path: string): (int, ref V)
{
	e := lookpaths.find(path);
	if(e == nil)
		return (0, nil);
	looktake(e);
	e.prev = looklast;
	looklast = looklast.next = e;
	return (1, e.v);
}

lookput(v: ref V)
{
	<-lookuplock;
	lookput0(v);
	lookuplock <-= 1;
}

lookput0(v: ref V)
{
	e := lookfirst;
	looktake(lookfirst);
	if(e.v != nil)
		lookpaths.del(e.v.path);
	e.v = v;
	lookpaths.add(e.v.path, e);
	e.prev = looklast;
	looklast = looklast.next = e;
}

walk(v: ref V, name: string): (ref V, string)
{
	if(name == "..") {
		if(v.p != nil)
			v = v.p;
		return (v, nil);
	}

	(hit, nv) := lookup(v.path+"/"+name);
	if(hit)
		return (nv, nil);

	err: string;
	(nv, err) = lwalk(v, name);
	if(nv != nil)
		lookput(nv);
	if(nv == nil && err == nil)
		err = Enotfound;
	return (nv, err);
}

namecmp(a, b: array of byte, unbotch: int): int
{
	n := min(len a, len b);
	for(i := 0; i < n; i++)
		if(a[i] != b[i])
			return int a[i]-int b[i];
	if(len a == len b)
		return 0;
	if(len a < len b)
		r := 1;
	else
		r = -1;
	if(unbotch)
		r = -r;
	return r;
}

Metablockmagic: con 16r5656fc79;
lwalk(v: ref V, name: string): (ref V, string)
{
	nm := array of byte name;
	ee := v.mt.e;
	nb := int ((ee.size+big (ee.dsize-1))/big ee.dsize);
	for(i := 0; i < nb; i++) {
		(d, err) := v.mt.get(i);
		if(err != nil)
			return (nil, err);
		mb := Metablock.unpack(d);
		if(mb == nil)
			return (nil, sprint("dir metablock: %r"));

		unbotch := g32(d, 0)==(Metablockmagic+1);

		s := 0;
		e := mb.nindex;
		while(s < e) {
			m := (s+e)/2;
			me := Metaentry.unpack(d, m);
			if(me == nil)
				return (nil, sprint("dir metaentry: %r"));

			o := me.offset+6;
			if(o+2 > len d)
				return (nil, "short metablock1");
			n := g16(d, o);
			o += 2;
			if(o+n > len d)
				return (nil, "short metablock2");
			denm := d[o:o+n];
			
			cmp := namecmp(denm, nm, unbotch);
			if(cmp < 0)
				s = m+1;
			if(cmp > 0)
				e = m;
			if(cmp != 0)
				continue;

			de := Direntry.unpack(d[me.offset:me.offset+me.size]);
			if(de == nil)
				return (nil, sprint("dir direntry: %r"));
				
			(ne, err0) := getentry(v, de.entry);
			if(err0 != nil)
				return (nil, err0);
			if(de.emode&Sys->DMDIR)
				(nme, err1) := getentry(v, de.mentry);
			if(err1 != nil)
				return (nil, err1);
			nv := V.mk(de, ne, nme, v);
			return (nv, nil);
		}
	}
	return (nil, nil);
}

# called with f.d.dirlock held
readdir(f: ref Fid, off: big, n: int): (array of byte, string)
{
	d := ref *f.d;
	if(off != d.off)
		return (nil, Ediroffset);
	dirs: list of array of byte;
	h := 0;
	for(;;) {
		if(d.mb == nil || d.me >= d.mb.nindex) {
			if(dflag) warn("readdir, next mb");
			# fetch & parse next mb
			me := f.v.mt.e;
			if(big d.b >= (me.size+big (me.dsize-1))/big me.dsize) {
				if(dflag) warn("readdir, was last mb");
				if(dirs == nil)
					return (array[0] of byte, nil);
				break;
			}
			err: string;
			(d.buf, err) = f.v.mt.get(d.b);
			if(err != nil)
				return (nil, err);
			d.mb = Metablock.unpack(d.buf);
			if(d.mb == nil)
				return (nil, sprint("metablock: %r"));
			d.b++;
			d.me = 0;
		}
		if(dflag) warn("readdir, next me");
		me := Metaentry.unpack(d.buf, d.me);
		if(me == nil)
			return (nil, sprint("metaentry: %r"));
		de := Direntry.unpack(d.buf[me.offset:me.offset+me.size]);
		if(de == nil)
			return (nil, sprint("direntry: %r"));
if(dflag) warn(sprint("direntry, elem %q, qid %bux, mode %ux, uid gid %q %q, entry %d, mentry %d", de.elem, de.qid, de.emode, de.uid, de.gid, de.entry, de.mentry));
		(ne, err) := getentry(f.v, de.entry);
		if(err != nil)
			return (nil, "getentry: "+err);
		nd := dir(de, ne.size);
		nn := styx->packdirsize(nd);
		if(h+nn > n)
			break;
		dirs = styx->packdir(nd)::dirs;
		d.me++;
		d.i++;
		h += nn;
	}
	if(dirs == nil)
		return (nil, Esmalldirread);
	buf := array[h] of byte;
	o := 0;
	for(l := rev(dirs); l != nil; l = tl l) {
		buf[o:] = hd l;
		o += len hd l;
	}
	d.off += big len buf;
	f.d = d;
	return (buf, nil);
}

read(f: ref Fid, off: big, n: int): (array of byte, string)
{
	e := f.v.t.e;
	b := int (off/big e.dsize);
	ee := big (b+1)*big e.dsize;
	if(ee > e.size)
		ee = e.size;
	(d, err) := f.v.t.get(b);
	if(err != nil)
		return (nil, err);
	nn := int (ee-off);
	if(n > nn)
		n = nn;
	o := int (off%big e.dsize);
	return (d[o:o+n], nil);
}

styxread(sfd: ref Sys->FD, c: chan of ref Tmsg, ec: chan of string)
{
	for(;;) {
		m := Tmsg.read(sfd, msize);
		if(m == nil) {
			ec <-= nil;
			return;
		}
		if(sflag) warn("9 <- "+m.text());
		c <-= m;
	}
}

styxwrite(sfd: ref Sys->FD, c: chan of ref Rmsg, ec: chan of string)
{
	for(;;) {
		m := <-c;
		if(sflag) warn("9 -> "+m.text());
		if(sys->write(sfd, d := m.pack(), len d) != len d)
			ec <-= sprint("write: %r");
	}
}

qid(d: ref Direntry): sys->Qid
{
	return sys->Qid(d.qid, d.mcount, (d.emode>>24)&16rff);
}

dir(d: ref Direntry, size: big): Sys->Dir
{
	return sys->Dir(d.elem, d.uid, d.gid, d.mid, qid(d), d.emode, d.atime, d.mtime, size, 0, 0);
}

stat(v: ref V): Sys->Dir
{
	return dir(v.d, v.t.e.size);
}

sha1(d: array of byte): array of byte
{
	dig := array[kr->SHA1dlen] of byte;
	kr->sha1(d, len d, dig, nil);
	return dig;
}

rev[T](l: list of T): list of T
{
	r: list of T;
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
}

g16(d: array of byte, o: int): int
{
	return int d[o+0]<<8 | int d[o+1]<<0;
}

g32(d: array of byte, o: int): int
{
	return g16(d, o)<<16 | g16(d, o+2)<<0;
}

min(a, b: int): int
{
	if(a < b)
		return a;
	return b;
}

pid(): int
{
	return sys->pctl(0, nil);
}

progctl(pid: int, s: string)
{
	sys->fprint(sys->open(sprint("/prog/%d/ctl", pid), sys->OWRITE), "%s", s);
}

killgrp(pid: int)
{
	progctl(pid, "killgrp");
}

fd2: ref Sys->FD;
warn(s: string)
{
	if(fd2 == nil)
		fd2 = sys->fildes(2);
	sys->fprint(fd2, "%s\n", s);
}

fail(s: string)
{
	warn(s);
	killgrp(pid());
	raise "fail:"+s;
}
