# -*-cperl-*-
#
# Crypt::GPG - An Object Oriented Interface to GnuPG.
# Copyright (c) 2000-2005 Ashish Gulhati <crypt-gpg at neomailbox.com>
#
# All rights reserved. This code is free software; you can
# redistribute it and/or modify it under the same terms as Perl
# itself.
#
# $Id: GPG.pm,v 1.52 2005/02/23 09:12:54 cvs Exp $

package Crypt::GPG;

use Carp;
use Fcntl;
use strict;
use English; 
use File::Path;
use Date::Parse;
use File::Temp qw( tempfile tempdir );
use IPC::Run qw( start pump finish timeout );
use vars qw( $VERSION $AUTOLOAD );

File::Temp->safe_level( File::Temp::STANDARD );
( $VERSION ) = '$Revision: 1.52 $' =~ /\s+([\d\.]+)/;

sub new {
  bless { GPGBIN         =>   'gpg',
	  FORCEDOPTS     =>   '--no-secmem-warning',
	  GPGOPTS        =>   '--lock-multiple --compress-algo 1 ' .
	                      '--cipher-algo cast5 --force-v3-sigs',
	  DELAY          =>   0,
	  PASSPHRASE     =>   '',
	  ARMOR          =>   1,
	  MARGINALS      =>   3,
	  DETACH         =>   1,
	  ENCRYPTSAFE    =>   1,
	  TEXT           =>   1,
	  SECRETKEY      =>   '',
	  DEBUG          =>   0,
	  TMPFILES       =>   'fileXXXXXX',
	  TMPDIRS        =>   'dirXXXXXX',
	  TMPDIR         =>   '/tmp',
	  TMPSUFFIX      =>   '.dat',
	  VKEYID         =>   '^.+$',
	  VRCPT          =>   '^.*$',
	  VPASSPHRASE    =>   '^.*$',
	  VNAME          =>   '^[a-zA-Z][\w\.\s\-\_]+$',
	  VEXPIRE        =>   '^\d+$',
	  VKEYSZ         =>   '^\d+$',
	  VKEYTYPE       =>   '^ELG-E$',
	  VTRUSTLEVEL    =>   '^[1-5]$',
	  VEMAIL         =>   '^[\w\.\-]+\@[\w\.\-]+\.[A-Za-z]{2,3}$'
	}, shift;
}

sub sign {
  my $self = shift; 

  return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
    and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;

  my $detach    = '-b' if $self->{DETACH}; 
  my $armor     = '-a' if $self->{ARMOR}; 
  my @extras    = grep { $_ } ($detach, $armor);

  my @secretkey = ('--default-key', ref($self->{SECRETKEY})?$self->{SECRETKEY}->{ID}:$self->{SECRETKEY});

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);

  my $message = join ('', @_); 
  $message .= "\n" unless $message =~ /\n$/s;
  $message =~ s/\n/\r\n/sg;
  print $tmpfh $message; close $tmpfh; 

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  local $SIG{CHLD} = 'IGNORE';

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, @secretkey,'--no-tty', '--status-fd', '1', '--command-fd', 
		  0, '-o-', '--sign', @extras, $tmpnam], \$in, \$out, \$err, timeout( 30 ));
  my $skip = 1; my $i = 0;
  local $SIG{CHLD} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';
  while ($skip) {
    pump $h until ($out =~ /NEED_PASSPHRASE (.{16}) (.{16}).*\n/g or
		   $out =~ /GOOD_PASSPHRASE/g);
    if ($2) {
      $in .= "$self->{PASSPHRASE}\n";
      pump $h until $out =~ /(GOOD|BAD)_PASSPHRASE/g;
      if ($1 eq 'GOOD') {
	$skip = 0;
      }
      else {
	$skip = 0 if $i++ == 2;
      }
    }
    else {
      finish $h;
      last;
    }
  }
  finish $h;
 
  my $info;
  if ($detach) {
    $out =~ /(-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----)/s;
    $info = $1;
  }
  else {
    $out =~ /(-----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----)/s;
    $info = $1;
  }
  unlink $tmpnam;
  return $info;
}

sub decrypt { shift->verify(@_); }

sub verify {
  my $self = shift; 
  my ($tmpfh3, $tmpnam3);

  return unless $self->{SECRETKEY} || $_[1];
  return unless $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;

  my ($tf, $ts, $td) = ($self->{TMPFILES}, $self->{TMPSUFFIX}, $self->{TMPDIR});
  my ($tmpfh, $tmpnam) = tempfile ($tf, DIR => $td, SUFFIX => $ts, UNLINK => 1);
  my ($tmpfh2, $tmpnam2) = tempfile ($tf, DIR => $td, SUFFIX => $ts, UNLINK => 1);

  my $ciphertext = ref($_[0]) ? join '', @{$_[0]} : $_[0];
  $ciphertext .= "\n" unless $ciphertext =~ /\n$/s;
  print $tmpfh $ciphertext; close $tmpfh;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  backtick ($self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS}, '--check-trustdb');

    local $SIG{CHLD} = 'IGNORE';
    local $SIG{PIPE} = 'IGNORE';

  my $x;
  if ($_[1]) {
    my $signature = ref($_[1]) ? join '', @{$_[1]} : $_[1];
    ($tmpfh3, $tmpnam3) = tempfile ($tf, DIR => $td, SUFFIX => $ts, UNLINK => 1);
    print $tmpfh3 $signature; close $tmpfh3;
    my $y = "$self->{GPGBIN} @opts --marginals-needed $self->{MARGINALS} --status-fd 1 --command-fd 0 --no-tty --verify $tmpnam $tmpnam3";
    $x = `$y`;
  }

  else {
    my ($in, $out, $err, $in_q, $out_q, $err_q);
    my $h = start ([$self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS},
                    '--status-fd', '1', '--command-fd', 0, '--yes', '--no-tty', 
		    '--decrypt', '-o', $tmpnam2, $tmpnam], 
		   \$in, \$out, \$err, timeout( 30 ));

    my $success = 0;
    while (1) {
      pump $h until ($out =~ /NEED_PASSPHRASE (.{16}) (.{16}).*\n/g
		     or $out =~ /(GOOD_PASSPHRASE)/g
		     or $out =~ /(D)(E)(C)RYPTION_FAILED/g or $out =~ /(N)(O)(D)ATA/g
		     or $out =~ /(SIG_ID)/g
		     or $out =~ /detached_signature.filename/g
		    );
      if ($3) {
	finish $h;
	last;
      }
      elsif ($2) {
	if ($2 eq ($self->keydb($self->{SECRETKEY}))[0]->{ID}) {
	  $in .= "$self->{PASSPHRASE}\n";
	  pump $h until $out =~ /(GOOD|BAD)_PASSPHRASE/g;
	  if ($1 eq 'GOOD') {
	    $success = 1;
	    pump $h;
	    finish $h; $x = $out; last;
	  }
	  next;
	}
	else {
	  $out = ''; $in .= "\n";
	}
      }
      elsif ($1) {
	$success = 1;
	pump $h;
	finish $h; $x = $out; last;
      }
    }
    
    
    unless ($success || $_[1]) {
      close $tmpfh2; unlink ($tmpnam2);
      return undef;
    }
  }

  # Format of $out for signatures:
  #
  # [GNUPG:] SIG_ID DPkOkpATuFPWl2yUR9bw7G6SULk 2005-02-05 1107574559
  # [GNUPG:] GOODSIG 48196CF147A781BD A 768 ELG-E <768ELG-E@test.com>
  # [GNUPG:] VALIDSIG 186D893EFEC3AF2F660CA2F548196CF147A781BD 2005-02-05 1107574559 0 3 0 17 2 00 186D893EFEC3AF2F660CA2F548196CF147A781BD
  # [GNUPG:] TRUST_ULTIMATE

  my $plaintext = join ('',<$tmpfh2>) || ''; 
  close $tmpfh2; unlink ($tmpnam2);

  return ($plaintext) 
    unless $x =~ /SIG_ID/s;

  my @signatures;
  $x =~ /SIG_ID \S+ (\S+ \S+).*(GOOD|BAD)SIG (\S{16}).*(?:TRUST_(\S+))?/sg;
  my $signature = {'Validity' => $2, 'KeyID' => $3, 
		   'Time' => $1, 'Trusted' => $4};
  $signature->{Time} = str2time ($signature->{Time}); 
  bless $signature, 'Crypt::GPG::Signature';
  return ($plaintext, $signature);
}

sub msginfo {
  my $self = shift; 
  my @return;
  
  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
 	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  warn join '',@{$_[0]};
  print $tmpfh join '',@{$_[0]}; close $tmpfh;
  
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my ($info) = backtick ($self->{GPGBIN}, @opts, '--status-fd', 1, '--no-tty', '--batch', $tmpnam); 
  $info =~ s/ENC_TO (.{16})/{push @return, $1}/sge; 
  unlink $tmpnam;
  return @return;
}

sub encrypt {
  my $self = shift; 
  my ($message, $rcpts) = @_;
  my $info;

  my $sign = $_[2] && $_[2] eq '-sign' ? '--sign' : '';
  my $armor = $self->{ARMOR} ? '-a' : '';

  if ($sign) {
    return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
      and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;
  }

  my @rcpts;
  if (ref($rcpts) eq 'ARRAY') {
    @rcpts = map { 
      return unless /$self->{VRCPT}/; 
      ('-r', $_) } @$rcpts;
  }
  else {
    return unless $rcpts =~ /$self->{VRCPT}/;
    @rcpts = ('-r', $rcpts);
  }

  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  my ($tmpfh2, $tmpnam2) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);

  $message = join ('', @$message) if ref($message) eq 'ARRAY'; 
  print $tmpfh $message; close $tmpfh;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, '--default-key', ref($self->{SECRETKEY})?$self->{SECRETKEY}->{ID}:$self->{SECRETKEY}) if $sign;
  push (@opts, $sign) if $sign; push (@opts, $armor) if $armor;

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                  '-o', $tmpnam2, @rcpts, '--encrypt', $tmpnam], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';
  my $pos;
  eval {
    pump $h until ($out =~ /(o)penfile.overwrite.okay/g
		   or $out =~ /(u)(n)trusted_key.override/g    #! Test
		   or $out =~ /(k)(e)(y) not found/g           #! Test
		   or $out =~ /(p)(a)(s)(s)phrase.enter/g);
    $pos = 1 if $1; $pos = 2 if $2; $pos = 3 if $3; $pos = 4 if $4;
  };
  return if $@;
  if ($pos == 4) {
    undef $pos; $out = '';
    $in .= "$self->{PASSPHRASE}\n";
    pump $h until ($out =~ /(o)penfile.overwrite.okay/g
		   or $out =~ /(u)(n)trusted_key.override/g  #! Test
		    or $out =~ /(I)(N)(V)_RECP/g              #! Test
		   or $out =~ /(p)(a)(s)(s)phrase.enter/g);  #! Test
    $pos = 1 if $1; $pos = 2 if $2; $pos = 3 if $3; $pos = 4 if $4;
    finish $h, return undef if $pos == 4;                    #! Test
  }

#  while (1) {
#    unless ($pos) {
#      ($pos, $err, $matched, $before, $after) = $expect->expect 
#	(undef, 'Overwrite', # '-re', '-----BEGIN PGP', 
#	 'Use this key anyway?', 'key not found');
#    }
#    return if $err;
    if ($pos == 2) {
      if ($self->{ENCRYPTSAFE}) {
	$in .= "N\n";
	finish $h;
	unlink $tmpnam;
	return;
      }
      else {
	$in .= "Y\n";
#	finish $h;
	pump $h until ($out =~ /(o)penfile.overwrite.okay/g
		       or $out =~ /(o)(p)enfile.askoutname/g);  #! Test
#		       or $out =~ /(I)(N)(V)_RECP/g              #! Test
#		       or $out =~ /(p)(a)(s)(s)phrase.enter/g);  #! Test
	$pos = 1 if $1; $pos = 2 if $2;
      }	
    }
    elsif ($pos == 3) {
      finish $h;
      unlink $tmpnam;
      return;
    }
#    else {
#      last;
#    }
#  }
  
  if ($pos == 1) {
    $in .= "Y\n";
    finish $h;
  }

  my @info = <$tmpfh2>; 
  close $tmpfh2;
  unlink $tmpnam2;
  $info = join '', @info;

  unlink $tmpnam;
  return $info;
}

sub addkey {
  my $self = shift;
  my ($key, $pretend, @keyids) = @_;

  $key = join ('', @$key) if ref($key) eq 'ARRAY'; 
  return if grep { $_ !~ /^[a-f0-9]+$/i } @keyids;

  my $tmpdir = tempdir( $self->{TMPDIRS}, 
		     DIR => $self->{TMPDIR}, CLEANUP => 1);
  my ($tmpfh, $tmpnam) = 
    tempfile( $self->{TMPFILES}, DIR => $self->{TMPDIR}, 
	      SUFFIX => $self->{TMPSUFFIX}, UNLINK => 1);
  print $tmpfh $key;

  my @pret1 = ('--options', '/dev/null', '--homedir', $tmpdir);
  my @pret2 = ('--keyring', "$tmpdir/pubring.gpg", 
	       '--secret-keyring', "$tmpdir/secring.gpg");
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  my @listopts = qw(--fingerprint --fingerprint --with-colons);

  backtick($self->{GPGBIN}, @opts, @pret1, '-v', '--import', $tmpnam);
  backtick ($self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS}, '--check-trustdb');
  my ($keylist) = backtick($self->{GPGBIN}, @opts, @pret1, '--marginals-needed',
			   $self->{MARGINALS}, '--check-sigs', @listopts, @keyids); 
  my ($seclist) = backtick($self->{GPGBIN}, @opts, @pret1,
			   '--list-secret-keys', @listopts);

  my @seckeys = grep { my $id = $_->{ID}; 
		       (grep { $id eq $_ } @keyids) ? $_ : '' } 
    $self->parsekeys(split /\n/,$seclist);
  my @ret = ($self->parsekeys(split /\n/,$keylist), @seckeys);

  if ($pretend) {
#! This hack needed to get real calc trusts for to-import keys. Test!
    backtick ($self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS}, '--check-trustdb');
    ($keylist) = backtick($self->{GPGBIN}, @opts, @pret2, '--marginals-needed',
			  $self->{MARGINALS}, '--check-sigs', @listopts); 

    my @realkeylist = grep { my $id = $_->{ID} if $_; 
			     $id and grep { $id eq $_->{ID} } @ret } 
#      map { ($_->{Keyring} eq "$tmpdir/secring.gpg" 
#	     or $_->{Keyring} eq "$tmpdir/pubring.gpg") ? $_ : 0 } 
	$self->parsekeys(split /\n/,$keylist);
    @ret = (@realkeylist, @seckeys);
  }
  else {
    if (@keyids) {
      my ($out) = backtick($self->{GPGBIN}, @opts, @pret1, "--export", '-a', @keyids);
      print $tmpfh $out; close $tmpfh;
    }
    backtick($self->{GPGBIN}, @opts, '-v', '--import', $tmpnam);
  }
  rmtree($tmpdir, 0, 1);
  unlink($tmpnam);
  return @ret;
}

sub export {
  my $self = shift; 
  my $key = shift; 
  my $id = $key->{ID}; 
  return unless $id =~ /$self->{VKEYID}/;

  my $armor = $self->{ARMOR} ? '-a' : '';
  my $secret = $key->{Type} eq 'sec' ? '-secret-keys' : '';
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, '--status-fd', '1');

  my ($out) = backtick($self->{GPGBIN}, @opts, "--export$secret", $armor, $id);
  $out;
}

sub keygen {
  my $self = shift; 
  my ($name, $email, $keytype, $keysize, $expire, $pass) = @_;

  return unless $keysize =~ /$self->{VKEYSZ}/ 
    and $keysize > 767 and $keysize < 4097
      and $pass =~ /$self->{VPASSPHRASE}/
	and $keytype =~ /$self->{VKEYTYPE}/ 
	  and $expire =~ /$self->{VEXPIRE}/ 
	    and $email =~ /$self->{VEMAIL}/
	      and $name =~ /$self->{VNAME}/ 
		and length ($name) > 4;

  my $bigkey = ($keysize > 1536);   
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  for (0..1) { 
    backtick ($self->{GPGBIN}, @opts, '--status-fd', '1', '--no-tty', '--gen-random', 0, 1); 
  }

  my $pid = open(GPG, "-|");
  return undef unless (defined $pid);

  if ($pid) {
    $SIG{CHLD} = 'IGNORE';
    return \*GPG;
  }
  else {
    my ($in, $out, $err, $in_q, $out_q, $err_q);
    my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                    '--gen-key'], \$in, \$out, \$err);
    local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';

    pump $h until $out =~ /keygen\.algo/g; $in .= "1\n";
    pump $h until $out =~ /keygen\.size/g; $in .= "$keysize\n";
    pump $h until $out =~ /keygen\.valid/g; $in .= "$expire\n";
    pump $h until $out =~ /keygen\.name/g; $in .= "$name\n";
    pump $h until $out =~ /keygen\.email/g; $in .= "$email\n";
    pump $h until $out =~ /keygen.comment/g; $in .= "\n";
    pump $h until $out =~ /passphrase\.enter/g; $out = ''; $in .= "$pass\n"; 
    pump $h until $out =~ /(PROGRESS primegen [\+\.\>\<\^]|KEY_CREATED)/g;
    $out = ''; my $x = ''; my $y = $1;
    while ($y !~ /KEY_CREATED/g) {
      print "$x\n"; 
      pump $h until $out =~ /(PROGRESS primegen [\+\.\>\<\^]|KEY_CREATED)/g;
      my $o = $out; $out = ''; $y .= $o;
      my @progress = ($o =~ /[\+\.\>\<\^]/g);
      $x = join "\n",@progress;
    }	
    print "|\n";
    finish $h;
    exit();
  }
}

sub keydb {
  my $self = shift; 
  my @ids = map { return unless /$self->{VKEYID}/; $_ } @_;
  my @moreopts = qw(--fingerprint --fingerprint --with-colons);
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  backtick ($self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS}, '--check-trustdb');
  my ($keylist) = backtick($self->{GPGBIN}, @opts, '--marginals-needed', $self->{MARGINALS},
			   '--no-tty', '--check-sigs', @moreopts, @ids); 
  my ($seclist) = backtick($self->{GPGBIN}, @opts,
			   '--no-tty', '--list-secret-keys', @moreopts, @ids); 
  my @keylist = split /\n(\s*\n)?/, $keylist;
  my @seclist = split /\n(\s*\n)?/, $seclist;
  $self->parsekeys (@keylist, @seclist);
}

sub keyinfo {
  shift->keydb(@_);
}

sub parsekeys {
  my $self=shift; my @keylist = @_;
  my @keys; my ($i, $subkey, $subnum, $uidnum) = (-1);
  my $keyring = '';
  $^W = 0;
  foreach (@keylist) {
    next if /^\-/;
    next if /^(gpg|tru):/;
    if (/^\//) {
      $keyring = $_; chomp $keyring;
      next;
    }
    if (/^(pub|sec)/) {
      $uidnum=-1; $subnum=-1; $subkey=0;
      my ($type, $trust, $size, $algorithm, $id, $created, 
	  $expires, $u2, $ownertrust, $uid) = split (':');
      $keys[++$i] = { 
		     Keyring    =>    $keyring,
		     Type       =>    $type,
		     Ownertrust =>    $ownertrust,
		     Bits       =>    $size,
		     ID         =>    $id,
		     Created    =>    $created,
		     Expires    =>    $expires,
		     Algorithm  =>    $algorithm,
		     Use        =>    ''
		    };
      push (@{$keys[$i]->{UIDs}}, { 'UID' => $uid, 'Calctrust' => $trust }), 
	$uidnum++ if $uid;
    }
    else {
      if (/^fpr:::::::::([^:]+):/) {
	my $fingerprint = $1; my $l = length $fingerprint;
	if ($l == 32) {
	  my @f = $fingerprint =~ /(..)/g;
	  $fingerprint = (join ' ', @f[0..7]) . '  ' . 
	    (join ' ', @f[8..15]);
	}
	elsif ($l == 40) {
	  my @f = $fingerprint =~ /(....)/g;
	  $fingerprint = (join ' ', @f[0..4]) . '  ' . 
	    (join ' ', @f[5..9]);
	}
	$subkey ?
	  $keys[$i]->{Subkeys}->[$subnum]->{Fingerprint} :
	  $keys[$i]->{Fingerprint} =  $fingerprint;
      }
      elsif (/^sub/) {
	$subnum++; $subkey      =     1;
	my ($type, $u1, $size, $algorithm, $id, 
	    $created, $expires) = split (':');
	$keys[$i]->{Subkeys}->[$subnum] = 
	  {
	   Bits                 =>    $size,
	   ID                   =>    $id,
	   Created              =>    $created,
	   Expires              =>    $expires,
	   Algorithm            =>    $algorithm
	  };
      }
      elsif (/^sig/) {
	my ($sig, $valid, $u2, $u3, $id, $date, 
	    $u4, $u5, $u6, $uid) = split (':');
	my ($pushto, $pushnum) = $subkey ? 
	  ('Subkeys',$subnum) : ('UIDs',$uidnum);
	push (@{$keys[$i]->{$pushto}->[$pushnum]->{Signatures}},
	      {	ID              =>    $id,
		Date            =>    $date,
		UID             =>    $uid,
		Valid           =>    $valid
	      } );
      }
      elsif (/^uid:(.?):.*:([^:]+):$/) {
	$subkey = 0; $uidnum++;
	push (@{$keys[$i]->{UIDs}}, { UID => $2, Calctrust => $1 });
      }
    }
  }
  $^W = 1;
  return map {bless $_, 'Crypt::GPG::Key'} @keys;
}

sub keypass {
  my $self = shift; 

  my ($key, $oldpass, $newpass) = @_;
  return unless $oldpass =~ /$self->{VPASSPHRASE}/ 
    and $newpass =~ /$self->{VPASSPHRASE}/
      and $key->{Type} eq 'sec';

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                 '--edit-key', $key->{ID}], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';

  pump $h until $out =~ /keyedit\.prompt/g; $in .= "passwd\n";
  pump $h until ($out =~ /GOOD_PASSPHRASE/g
		 or $out =~ /(passphrase\.enter)/g);
  
  unless ($1) {
    finish $h, return if $oldpass;
  }
  else {
    $^W = 0; /()/; $^W = 1; $out = '';
    $in .= "$oldpass\n";
    pump $h until ($out =~ /BAD_PASSPHRASE/g                #! Test
		   or $out =~ /(passphrase\.enter)/g);
    unless ($1) {
      finish $h;
      return;
    }
  }
  $^W = 0; /()/; $^W = 1; $out = '';
  $in .= "$newpass\n";
  pump $h until ($out =~ /change_passwd\.empty\.okay/g
		 or $out =~ /(keyedit\.prompt)/g);
  unless ($1) {
    $in .= "Y\n";
    pump $h until $out =~ /keyedit\.prompt/g;
  }
  $in .= "quit\n";
  pump $h until $out =~ /keyedit\.save\.okay/g;
  $in .= "Y\n";
  finish $h;
  return 1;
}

sub keytrust {
  my $self = shift; 
  my ($key, $trustlevel) = @_;
  return unless $trustlevel =~ /$self->{VTRUSTLEVEL}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty',
                 '--status-fd', '1', '--command-fd', 0,
                 '--edit-key', $key->{ID}], 
                 \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';
  pump $h until $out =~ /keyedit\.prompt/g; $in .= "trust\n";
  pump $h until $out =~ /edit_ownertrust\.value/g; $in .= "$trustlevel\n";
  if ($trustlevel == 5) {
    pump $h until $out =~ /edit_ownertrust\.set_ultimate\.okay/g; $in .= "Y\n";
  }
  pump $h until $out =~ /keyedit\.prompt/g; $in .= "quit\n";
  finish $h;
  return 1;  
}

sub keyprimary {
}

sub certify {
  my $self = shift; 
  my ($key, $local, $class, @uids) = @_; 

  return unless $self->{SECRETKEY} =~ /$self->{VKEYID}/ 
    and $self->{PASSPHRASE} =~ /$self->{VPASSPHRASE}/;

  return unless @uids and !grep { $_ =~ /\D/; } @uids; 
  my $i = 0; my $ret = 0;

  ($key) = $self->keydb($key);
  my $signingkey = ($self->keydb($self->{SECRETKEY}))[0]->{ID};

  # Check if already signed.
  return 1 unless grep { !grep { $signingkey eq $_->{ID} } 
			   @{$_->{Signatures}} } 
    (@{$key->{UIDs}})[@uids];

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));
  push (@opts, '--default-key', $self->{SECRETKEY});

  my ($in, $out, $err, $in_q, $out_q, $err_q);

  my $h = start ([$self->{GPGBIN}, @opts, '--status-fd', '1', '--command-fd', 0, '--no-tty',
                 '--edit-key', $key->{ID}], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';

  for (@uids) {
    my $uid = $_+1;
    pump $h until ($out =~ /keyedit\.prompt/g); 

# Old hack to make UID numbers correspond correctly.
#    my $info = $out; $out = '';
#    $info =~ /\((\d+)\)\./; my $primary = $1;
#    unless ($primary == 1) {
#      if ($uid == 1) {
#	$uid = $primary;
#      }
#      elsif ($uid <= $primary) {
#	$uid--;
#      }
#    }

    $in .= "uid $uid\n"; 
  }
  pump $h until ($out =~ /keyedit\.prompt/g); 
  $out = '';
  $in .= $local ? "lsign\n" : "sign\n"; 

  pump $h until ($out =~ /(s)ign_uid\.class/g
		 or $out =~ /keyedit\.prompt/g);
  my $fix = $1;
  unless ($1) {
    $out = ''; $in .= "\n";
    pump $h until ($out =~ /(s)ign_uid\.class/g
		 or $out =~ /keyedit\.prompt/g);
    $fix = $1;
  }
  
  if ($fix) {
    $in .= "$class\n";
    pump $h until ($out =~ /sign_uid\.okay/g);
    $^W = 0; /()/; $^W = 1; $out = ''; $in .= "Y\n"; 
    pump $h until ($out =~ /passphrase\.enter/g
		   or $out =~ /(keyedit.prompt)/g);
    $ret=1;
    unless ($1) {
      $out = ''; $^W = 0; /()/; $^W = 1; $in .= "$self->{PASSPHRASE}\n"; 
      pump $h until ($out =~ /keyedit\.prompt/g
		     or $out =~ /(BAD_PASSPHRASE)/g);
      $ret=0 if $1;
    }
  }
  $in .= "quit\n";
  if ($ret) {
    pump $h until ($out =~ /save\.okay/g or $out =~ /(k)eyedit\.prompt/g);
    $in .= "Y\n" unless $1;
  }
  finish $h;
  $ret;  
}

sub delkey {
  my $self = shift; 
  my $key = shift; 
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my $del = $key->{Type} eq 'sec' ?
    '--delete-secret-and-public-key':'--delete-key';
  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                 $del, $key->{ID}], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';
  pump $h until ($out =~ /delete it first\./g or $out =~ /(delete_key)(.secret)?.okay/g); 
                       #! ^^^^^^^^^^^^^^^^^ to-fix.
  finish $h, return undef unless $1; 
  $in .= "Y\n";
  if ($key->{Type} eq 'sec') {
    pump $h until $out =~ /delete_key.okay/g; $in .= "Y\n";
  }
  finish $h;
  return 1;
}

sub disablekey {
  my $self = shift; 
  my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                 '--edit-key', $key->{ID}], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';
  pump $h until ($out =~ /been disabled/g or $out =~ /(keyedit\.prompt)/g); 
                       #! ^^^^^^^^^^^^^ to-fix.
  finish $h, return undef unless $1; 
  $in .= "disable\n";
  pump $h until $out =~ /keyedit\.prompt/g; $in .= "quit\n";
  finish $h;
  return 1;
}

sub enablekey {
  my $self = shift; 
  my $key = shift;
  return unless $key->{ID} =~ /$self->{VKEYID}/;

  my @opts = (split (/\s+/, "$self->{FORCEDOPTS} $self->{GPGOPTS}"));

  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([$self->{GPGBIN}, @opts, '--no-tty', '--status-fd', '1', '--command-fd', 0,
                 '--edit-key', $key->{ID}], \$in, \$out, \$err, timeout( 30 ));
  local $SIG{CHLD} = 'IGNORE'; local $SIG{PIPE} = 'IGNORE';
  pump $h until ($out =~ /been disabled/g or $out =~ /(keyedit\.prompt)/g); 
                       #! ^^^^^^^^^^^^^ to-fix.
  finish $h, return undef unless $1; 
  $in .= "enable\n";
  pump $h until $out =~ /keyedit\.prompt/g; $in .= "quit\n";
  finish $h;
  return 1;
}

sub backtick {
  my ($in, $out, $err, $in_q, $out_q, $err_q);
  my $h = start ([@_], \$in, \$out, \$err, timeout( 10 ));
  local $SIG{CHLD} = 'IGNORE';
  local $SIG{PIPE} = 'IGNORE';
  finish $h;
  return ($out, $err);
}

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
#  warn "FOO $auto $_[0]\n";
  if ($auto =~ /^(passphrase|secretkey|armor|gpgbin|gpgopts|delay|marginals|
                  detach|encryptsafe|debug|tmpdir)$/x) {
    return $self->{"\U$auto"} unless defined $_[0];
    $self->{"\U$auto"} = shift;
  }
  elsif ($auto eq 'DESTROY') {
  }
  else {
    croak "Could not AUTOLOAD method $auto.";
  }
}

package Crypt::GPG::Signature;
use vars qw( $AUTOLOAD );
use Carp;

sub AUTOLOAD {
  my $self = shift; (my $auto = $AUTOLOAD) =~ s/.*:://;
  if ($auto =~ /^(validity|keyid|time|trusted)$/) {
    return $self->{"KeyID"} if ( $auto eq "keyid" );
    return $self->{"\u$auto"};
  }
  elsif ($auto eq 'DESTROY') {
  }
  else {
    croak "Could not AUTOLOAD method $auto.";
  }
}

'True Value';
__END__

=head1 NAME 

Crypt::GPG - An Object Oriented Interface to GnuPG.

=head1 VERSION

 $Revision: 1.52 $
 $Date: 2005/02/23 09:12:54 $

=head1 SYNOPSIS

  use Crypt::GPG;
  my $gpg = new Crypt::GPG;

  $gpg->gpgbin('/usr/bin/gpg');      # The GnuPG executable.
  $gpg->secretkey('0x2B59D29E');     # Set ID of default secret key.
  $gpg->passphrase('just testing');  # Set passphrase.

  # Sign a message:

  my $sign = $gpg->sign('testing again');

  # Encrypt a message:

  my @encrypted = $gpg->encrypt ('top secret', 'test@bar.com');

  # Get message info:

  my @recipients = $gpg->msginfo($encrypted);

  # Decrypt a message.

  my ($plaintext, $signature) = $gpg->verify($encrypted);

  # Key generation:

  $status = $gpg->keygen 
    ('Test', 'test@foo.com', 'ELG-E', 2048, 0, 'test passphrase');
  print while (<$status>); close $status;

  # Key database manipulation:

  $gpg->addkey($key, @ids);
  @keys = $gpg->keydb(@ids);

  # Key manipulation:

  $key = $keys[0];
 
  $gpg->delkey($key);
  $gpg->disablekey($key);
  $gpg->enablekey($key);
  $gpg->keypass($key, $oldpassphrase, $newpassphrase);
  $keystring = $gpg->export($key);

=head1 DESCRIPTION

The Crypt::GPG module provides access to the functionality of the
GnuPG (www.gnupg.org) encryption tool through an object oriented
interface. 

It provides methods for encryption, decryption, signing, signature
verification, key generation, key certification, export and
import. Key-server access is on the todo list.

This release of the module may create compatibility issues with
previous versions. If you find any such problems, or any bugs or
documentation errors, please do report them to
crypt-gpg at neomailbox.com.

=head1 CONSTRUCTOR

=over 2

=item B<new()>

Creates and returns a new Crypt::GPG object.

=back

=head1 DATA METHODS

=over 2

=item B<gpgbin($path)>

Sets the B<GPGBIN> instance variable which gives the path to the GnuPG
binary.

=item B<gpgopts($opts)>

Sets the B<GPGOPTS> instance variable which may be used to pass
additional options to the GnuPG binary. For proper functioning of this
module, it is advisable to always include '--lock-multiple' in the
GPGOPTS string.

=item B<delay($seconds)>

Sets the B<DELAY> instance variable. This is no longer necessary (nor
used) in the current version of the module, but remains so existing
scripts don't break.

=item B<secretkey($keyid)>

Sets the B<SECRETKEY> instance variable which may be a KeyID or a
username. This is the ID of the default key to use for signing.

=item B<passphrase($passphrase)>

Sets the B<PASSPHRASE> instance variable, required for signing and
decryption.

=item B<text($boolean)>

Sets the B<TEXT> instance variable. If set true, GnuPG will use
network-compatible line endings for proper cross-platform
compatibility and the plaintext will gain a newline at the end, if it
does not already have one.

=item B<armor($boolean)>

Sets the B<ARMOR> instance variable, controlling the ASCII armoring of
output. The default is to use ascii-armoring. The module has not been
tested with this option turned off, and most likely will not work if
you switch this off.

=item B<detach($boolean)>

Sets the B<DETACH> instance variable. If set true, the sign method
will produce detached signature certificates, else it won't. The
default is to produce detached signatures.

=item B<encryptsafe($boolean)>

Sets the B<ENCRYPTSAFE> instance variable. If set true, encryption
will fail if trying to encrypt to a key which is not trusted. This is
the default. Turn this off if you want to encrypt to untrusted keys.

=item B<debug($boolean)>

Sets the B<DEBUG> instance variable which causes the raw output of
Crypt::GPG's interaction with the GnuPG binary to be dumped to
STDOUT. By default, debugging is off.

=back

=head1 OBJECT METHODS

=over 2

=item B<sign(@message)>

Signs B<@message> with the secret key specified with B<secretkey()>
and returns the result as a string.

=item B<decrypt(\@message, [\@signature])>

This is just an alias for B<verify()>

=item B<verify(\@message, [\@signature])>

Decrypts and/or verifies the message in B<@message>, optionally using
the detached signature in B<@signature>, and returns a list whose
first element is plaintext message as a string. If the message was
signed, a Crypt::GPG::Signature object is returned as the second
element of the list.

The Crypt::GPG::Signature object can be queried with the following
methods:

   $sig->validity();    # 'GOOD', 'BAD', or 'UNKNOWN'
   $sig->keyid();       # ID of signing key
   $sig->time();        # Time the signature was made
   $sig->trusted();     # Signature trust level 

=item B<msginfo(@ciphertext)>

Returns a list of the recipient key IDs that B<@ciphertext> is
encrypted to.

=item B<encrypt($plaintext, $keylist, [-sign] )>

Encrypts B<$plaintext> with the public keys of the recipients listed
in B<$keylist> and returns the result in a string, or B<undef> if
there was an error while processing. Returns undef if any of the keys
are not found.

Either $plaintext or $keylist may be specified as either an arrayref
or a simple scalar.  

If $plaintext is a an arrayref, it will be join()ed without
newlines. 

If you want to encrypt to multiple recipients, you must use the
arrayref version of $keylist. A scalar $keylist works for only a
single key ID.

If the -sign option is provided, the message will be signed before
encryption. The secret key and passphrase must be set for signing to
work. They can be set with the secretkey() and passphrase() methods.

=item B<addkey($key, $pretend, @keyids)>

Adds the keys given in B<$key> to the user's key ring and returns a
list of Crypt::GPG::Key objects corresponding to the keys that were
added. $key may be a string or an array reference. 

If B<$pretend> is true, it pretends to add the key and creates the key
object, but doesn't actually perform the key addition.

Optionally, a list of key IDs may be specified. If a list of key IDs
is specified, only keys that match those IDs will be imported. The
rest will be ignored.

=item B<export($key)>

Exports the key specified by the Crypt::GPG::Key object B<$key> and
returns the result as a string.

=item B<keygen($name, $email, $keytype, $keysize, $expire, $passphrase)>

Creates a new keypair with the parameters specified. The only
supported B<$keytype> currently is 'ELG-E'. B<$keysize> can be any of
1024, 2048, 3072 or 4096. Returns undef if there was an error,
otherwise returns a filehandle that reports the progress of the key
generation process similar to the way GnuPG does. The key generation
is not complete till you read an EOF from the returned filehandle.

=item B<certify($keyid, $local, @uids)>

Certifies to the authenticity of UIDs of the key with ID $keyid. If
$local is true, the certification will be non-exportable. The @uids
parameter should contain the list of UIDs to certify (the first UID of
a key is 0).

=item B<keydb(@keyids)>

Returns an array of Crypt::GPG::Key objects corresponding to the Key
IDs listed in B<@keyids>. This method used to be called B<keyinfo> and
that is still an alias to this method.

=item B<parsekeys(@keylist)>

Parses a raw GnuPG formatted key listing in B<@keylist> and returns an
array of Crypt::GPG::Key objects.

=item B<keypass($key, $oldpass, $newpass)>

Change the passphrase for a key. Returns true if the passphrase change
succeeded, false if not, or undef if there was an error.

=item B<delkey($keyid)>

Deletes the key specified by the Crypt::GPG::Key object B<$key> from
the user's key ring. Returns undef if there was an error, or 1 if the
key was successfully deleted.

=item B<disablekey($keyid)>

Disables the key specified by the Crypt::GPG::Key object B<$key>.

=item B<enablekey($keyid)>

Enables the key specified by the Crypt::GPG::Key object B<$key>.

=back

=head1 Crypt::GPG::Signature

=over 2

  Documentation coming soon.

=back

=head1 Crypt::GPG::Key

=over 2

  Documentation coming soon.

=back

=head1 TODO

=over 2

=item * 

Key server access.

=item *

More complete key manipulation interface.

=item * 

Filehandle interface to handle large messages.

=back

=head1 BUGS

=over 2

=item * 

Error checking needs work. 

=item * 

Some key manipulation functions are missing. 

=item * 

The method call interface is subject to change in future versions.

=item * 

The current implementation will probably eat up all your RAM if you
try to operate on huge messages. In future versions, this will be
addressed by reading from and returning filehandles, rather than using
in-core data.

=item * 

Methods may break if you don't use ASCII armoring.

=back

=head1 CHANGELOG

=over 2

$Log: GPG.pm,v $
Revision 1.52  2005/02/23 09:12:54  cvs

 - Overhauled to use IPC::Run instead of Expect.

 - Test suite split up into multiple scripts.

Revision 1.42  2002/12/11 03:33:19  cvs

 - Fixed bug in certify() when trying to certify revoked a key.

 - Applied dharris\x40drh.net's patch to allow for varying date formats
   between gpg versions, and fix time parsing and the
   Crypt::GPG::Signature autoloaded accessor functions.

Revision 1.40  2002/09/23 23:01:53  cvs

 - Fixed a bug in keypass()

 - Documentation fixes.

Revision 1.37  2002/09/21 02:37:49  cvs

 - Fixed signing option in encrypt.

Revision 1.36  2002/09/21 00:03:29  cvs

 - Added many tests and fixed a bunch of bugs.

Revision 1.34  2002/09/20 19:07:11  cvs

 - Extensively modified formatting to make the code easier to
   read. All lines are now < 80 chars.

 - Removed all instances of invoking a shell.

 - Misc. other stuff.

Revision 1.31  2002/09/20 16:38:45  cvs

 - Cleaned up export and addkey. Fixed(?) addkey clobbering trustdb
   problem (thanks to jrray\x40spacemeat.com for the patch). Added
   support for signature verification on addkey pretend.

 - No calls to POSIX::tmpnam remain (thanks to radek\x40karnet.pl and
   jrray\x40spacemeat.com for suggesting File::Temp).

Revision 1.30  2002/09/20 15:25:47  cvs

 - Fixed up tempfile handling and eliminated calls to the shell in
   encrypt(), sign() and msginfo(). Passing all currently defined
   tests. 

 - Hopefully also fixed signing during encryption and verification of
   detached signatures. Not tested this yet.

Revision 1.29  2002/09/20 11:19:02  cvs

 - Removed hack to Version: string. Only the Comment: string in GPG
   output is now modified by Crypt::GPG. (Thanks to
   eisen\x40schlund.de for pointing out the bug here)

 - Removed code that incorrectly replaced 'PGP MESSAGE' with 'PGP
   SIGNATURE' on detached signatures. (Thanks to ddcc\x40mit.edu for
   pointing this out).

 - Fixed up addkey() to properly handle pretend mode and to
   selectively import only requested key IDs from a key block.

 - parsekeys() now also figures out which keyring a key belongs to.

 - Added certify() method, to enable certifying keys.

 - Added Crypt::GPG::Signature methods - validity(), keyid(), time()
   and trusted().

=back

=head1 AUTHOR

Crypt::GPG is Copyright (c) 2000-2005 Ashish Gulhati
<crypt-gpg at neomailbox.com>. All Rights Reserved.

=head1 ACKNOWLEDGEMENTS

Thanks to Barkha, my sunshine. And to the GnuPG team and everyone
who writes free software.

=head1 LICENSE

This code is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 BUGS REPORTS, PATCHES, FEATURE REQUESTS

Are very welcome. Email crypt-gpg at neomailbox.com.    

=cut

