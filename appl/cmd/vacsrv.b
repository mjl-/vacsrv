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
	Table: import tables;
include "venti.m";
	venti: Venti;
	Vmsg, Entry, Score, Session: import venti;
include "vac.m";
	vac: Vac;
	Direntry, Metablock, Metaentry: import vac;

Vacsrv: module {
	init:	fn(nil: ref Draw->Context, args: list of string);
};

vfd: ref Sys->FD; # xxx

dflag: int;
addr := "$venti";
tflag: int;
sflag: int;
Vflag: int;

zeroscore: Score;
top: array of ref Entry;
root: ref Direntry;
msize: int;
mtpt: string;

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

# director open for reading
D: adt {
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
	t:	ref Hashtree;
	mt:	ref Hashtree;
	p:	ref V;
};

Hashtree: adt {
	e:	ref Entry;

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
	arg->setusage(arg->progname()+" [-dtsV] [-a addr] [-m mtpt] score");
	while((c := arg->opt()) != 0)
		case c {
		'd' =>	dflag++;
		'a' =>	addr = arg->earg();
		'm' =>	mtpt = arg->earg();
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

	addr = dial->netmkaddr(addr, "net", "venti");
	cc := dial->dial(addr, nil);
	if(cc == nil)
		fail(sprint("dial: %r"));
	vfd = cc.dfd;
	ss := Session.new(vfd);
	if(ss == nil)
		fail(sprint("handshake: %r"));

	dr := vread(s, venti->Roottype, venti->Rootsize);
	if(dr == nil)
		fail(sprint("reading root score: %r"));
	r := venti->unpackroot(dr);
	if(r == nil)
		fail(sprint("parsing root score: %r"));
	say("have root");

	td := vread(r.score, venti->Dirtype, 3*venti->Entrysize);
	if(td == nil)
		fail(sprint("reading root directory: %r"));
	top = array[3] of ref Entry;
	for(i := 0; i < len top; i++) {
		e := venti->unpackentry(td[i*venti->Entrysize:(i+1)*venti->Entrysize]);
		if(e == nil)
			fail(sprint("root dir entry: %r"));
		top[i] = e;
	}
	say("have root entries");

	rd := vread(top[2].score, venti->Datatype, 8*1024);
	if(rd == nil)
		fail(sprint("reading root entry: %r"));
	mb := Metablock.unpack(rd);
	if(mb == nil)
		fail(sprint("parsing root metablock: %r"));
	rme := Metaentry.unpack(rd, 0);
	if(rme == nil)
		fail(sprint("parsing root metaentry: %r"));
	root = Direntry.unpack(rd[rme.offset:rme.offset+rme.size]);
	if(root == nil)
		fail(sprint("parsing root direntry: %r"));
	say("have root entry");

	if(mtpt == nil)
		return main(sys->fildes(0));

	if(sys->pipe(fds := array[2] of ref Sys->FD) < 0)
		fail(sprint("pipe: %r"));
	spawn main(fds[0]);
	if(sys->mount(fds[1], nil, mtpt, Sys->MREPL, nil) < 0)
		fail(sprint("mount: %r"));
}

main(sfd: ref Sys->FD)
{
	mm := Tmsg.read(sfd, 128);
	if(mm == nil)
		fail(sprint("reading Tversion: %r"));
	if(sflag) warn("<- "+mm.text());
	pick m := mm {
	Readerror =>
		fail("reading Tversion: "+m.error);
	* =>
		fail("first 9P2000 message from client not Tversion");
	Version =>
		rm := ref Rmsg.Version(m.tag, m.msize, "unknown");
		(v, nil) := str->splitstrl(m.version, ".");
		if(v == "9P2000")
			rm.version = v;
		if(sflag) warn("-> "+rm.text());
		if(sys->write(sfd, d := rm.pack(), len d) != len d)
			fail(sprint("write 9P2000 Rversion: %r"));
		msize = m.msize;
	}

	stc := chan[1] of ref Tmsg;
	src := chan[1] of ref Rmsg;
	serrc := chan of string;

	spawn styxread(sfd, stc, serrc);
	spawn styxwrite(sfd, src, serrc);

	fids := Table[ref Fid].new(31, nil);

	for(;;)
	alt {
	e := <-serrc =>
		fail(e);

	tm := <-stc =>
		pick m := tm {
		Readerror =>
			fail("9P2000 read error: "+m.error);
		Version =>
			fids = fids.new(31, nil);
			(v, nil) := str->splitstrl(m.version, ".");
			if(v != "9P2000")
				src <-= ref Rmsg.Version(m.tag, m.msize, "unknown");
			else {
				src <-= ref Rmsg.Version(m.tag, m.msize, v);
				msize = m.msize;
			}
		Attach =>
			if(m.afid != styx->NOFID)
				src <-= ref Rmsg.Error(m.tag, "no auth");
			else if(fids.find(m.fid) != nil)
				src <-= ref Rmsg.Error(m.tag, Efidinuse);
			else {
				src <-= ref Rmsg.Attach(m.tag, sys->Qid(root.qid, root.mcount, sys->QTDIR));
				f := ref Fid(0, nil, ref V(root, Hashtree.mk(top[0]), Hashtree.mk(top[1]), nil));
				fids.add(m.fid, f);
			}
		Flush =>
			src <-= ref Rmsg.Flush(m.tag);
		Walk =>
			f := fids.find(m.fid);
			if(f != nil)
				say(sprint("walk, fid: name %q, score %s", f.v.d.elem, f.v.t.e.score.text()));

			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else if(m.fid != m.newfid && fids.find(m.newfid) != nil)
				src <-= ref Rmsg.Error(m.tag, Efidinuse);
			else if(f.open)
				src <-= ref Rmsg.Error(m.tag, Efidopen);
			else if(len m.names == 0) {
				nf := ref Fid(0, nil, f.v);
				fids.add(m.newfid, nf);
				src <-= ref Rmsg.Walk(m.tag, array[0] of sys->Qid);
			} else {
				qids := array[len m.names] of sys->Qid;
				err: string;
				v := f.v;
				for(i := 0; i < len m.names; i++) {
					nv: ref V;
					(nv, err) = walk(v, m.names[i]);
					if(nv == nil)
						break;
					v = nv;
					qids[i] = sys->Qid(v.d.qid, v.d.mcount, (v.d.emode>>24)&16rff);
				}
				if(i == 0)
					src <-= ref Rmsg.Error(m.tag, err);
				else {
					src <-= ref Rmsg.Walk(m.tag, qids);
					nf := ref Fid(0, nil, v);
					fids.add(m.newfid, nf);
				}
			}
		Open =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else if(m.mode != sys->OREAD)
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
				if(f.v.t.e.flags&venti->Entrydir)
					(d, err) := readdir(f, m.offset, min(msize-24, m.count));
				else
					(d, err) = read(f, m.offset, min(msize-24, m.count));
				if(err != nil)
					src <-= ref Rmsg.Error(m.tag, err);
				else
					src <-= ref Rmsg.Read(m.tag, d);
			}
		Clunk or
		Remove =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			fids.del(m.fid);

			if(tagof m == tagof Tmsg.Clunk)
				src <-= ref Rmsg.Clunk(m.tag);
			else
				src <-= ref Rmsg.Error(m.tag, Enowrite);
		Stat =>
			f := fids.find(m.fid);
			if(f == nil)
				src <-= ref Rmsg.Error(m.tag, Ebadfid);
			else
				src <-= ref Rmsg.Stat(m.tag, stat(f));

		Auth =>
			src <-= ref Rmsg.Error(m.tag, "no auth");
		Create =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		Write =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		Wstat =>
			src <-= ref Rmsg.Error(m.tag, Enowrite);
		}
	}
}

Hashtree.mk(e: ref Entry): ref Hashtree
{
	return ref Hashtree(e);
}

Hashtree.get(t: self ref Hashtree, b: int): (array of byte, string)
{
say(sprint("t.get, b %d", b));
	s := t.e.score;

	eb := int (t.e.size/big t.e.dsize);
	if(b > eb)
		raise "block not in tree";

	if(t.e.depth > 0) {
		pp := t.e.psize/venti->Scoresize;
		pt := pp**(t.e.depth-1);
		xb := b;
		for(i := 0; i < t.e.depth; i++) {
			d := vread(s, venti->Pointertype0+i, t.e.psize);
			if(d == nil)
				return (nil, sprint("venti read: %r"));
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
	r := vread(s, dt, t.e.dsize);
	if(r == nil)
		return (nil, sprint("venti read: %r"));
	if(len r < t.e.dsize) {
		n := t.e.size-big b*big t.e.dsize;
		if(n > big t.e.dsize)
			n = big t.e.dsize;
		if(len r < int n) {
			if(dt == venti->Dirtype)
				return (nil, "zero truncation for Dirtype");
			nr := array[int n] of {* => byte 0};
			nr[:] = r;
			r = nr;
		}
	}
	return (r, nil);
}

vread(s: Score, t, nmax: int): array of byte
{
	if(zeroscore.eq(s))
		return array[0] of byte;
	tt := ref Vmsg.Tread(1, 0, s, t, nmax);
	if(tflag) warn("-> "+tt.text());
	if(sys->write(vfd, td := tt.pack(), len td) != len td)
		return nil;
	(rr, err) := Vmsg.read(vfd);
	if(err != nil) {
		sys->werrstr("vmsg read: "+err);
		return nil;
	}
	if(tflag) warn("<- "+rr.text());
	pick r := rr {
	Rread =>
		if(Vflag && !s.eq(ns := Score(sha1(r.data)))) {
			sys->werrstr(sprint("bad data from venti server, requested %s, got %s", s.text(), ns.text()));
			return nil;
		}
		return r.data;
	Rerror =>
		sys->werrstr("venti read: "+r.e);
		return nil;
	* =>
		sys->werrstr("unexpected venti response");
		return nil;
	}
}

getentry(v: ref V, i: int): (ref Entry, string)
{
say(sprint("getentr, i %d", i));
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

walk(v: ref V, name: string): (ref V, string)
{
	if(name == "..") {
		if(v.p != nil)
			v = v.p;
		return (v, nil);
	}
	e := v.mt.e;
	nb := int ((e.size+big (e.dsize-1))/big e.dsize);
	for(i := 0; i < nb; i++) {
		(d, err) := v.mt.get(i);
		if(err != nil)
			return (nil, err);
		mb := Metablock.unpack(d);
		if(mb == nil)
			return (nil, sprint("dir metablock: %r"));
		for(j := 0; j < mb.nindex; j++) {
			me := Metaentry.unpack(d, j);
			if(me == nil)
				return (nil, sprint("dir metaentry: %r"));
			de := Direntry.unpack(d[me.offset:me.offset+me.size]);
			if(de == nil)
				return (nil, sprint("dir direntry: %r"));
			if(de.elem == name) {
				(ne, err0) := getentry(v, de.entry);
				if(err0 != nil)
					return (nil, err0);
				(nme, err1) := getentry(v, de.mentry);
				if(err1 != nil)
					return (nil, err1);
				nv := ref V(de, Hashtree.mk(ne), Hashtree.mk(nme), v);
				return (nv, nil);
			}
		}
	}
	return (nil, Enotfound);
}

readdir(f: ref Fid, off: big, n: int): (array of byte, string)
{
	if(f.d == nil || f.d.off == big 0)
		f.d = ref D(big 0, 0, 0, nil, 0, nil);
	d := ref *f.d;
	if(off != d.off)
		return (nil, Ediroffset);
	dirs: list of array of byte;
	h := 0;
	for(;;) {
		if(d.mb == nil || d.me >= d.mb.nindex) {
			say("readdir, next mb");
			# fetch & parse next mb
			me := f.v.mt.e;
			if(big d.b >= (me.size+big (me.dsize-1))/big me.dsize) {
				say("readdir, was last mb");
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
		say("readdir, next me");
		me := Metaentry.unpack(d.buf, d.me);
		if(me == nil)
			return (nil, sprint("metaentry: %r"));
		de := Direntry.unpack(d.buf[me.offset:me.offset+me.size]);
		if(de == nil)
			return (nil, sprint("direntry: %r"));
say(sprint("direntry, elem %q, qid %bux, mode %ux, uid gid %q %q, entry %d, mentry %d", de.elem, de.qid, de.emode, de.uid, de.gid, de.entry, de.mentry));
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
			ec <-= "eof";
			return;
		}
		if(sflag) warn("<- "+m.text());
		c <-= m;
	}
}

styxwrite(sfd: ref Sys->FD, c: chan of ref Rmsg, ec: chan of string)
{
	for(;;) {
		m := <-c;
		if(sflag) warn("-> "+m.text());
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

stat(f: ref Fid): Sys->Dir
{
	return dir(f.v.d, f.v.t.e.size);
}

sha1(d: array of byte): array of byte
{
	st := kr->sha1(d, len d, nil, nil);
	dig := array[kr->SHA1dlen] of byte;
	kr->sha1(nil, 0, dig, st);
	return dig;
}

rev[T](l: list of T): list of T
{
	r: list of T;
	for(; l != nil; l = tl l)
		r = hd l::r;
	return r;
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

say(s: string)
{
	if(dflag)
		warn(s);
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
