# Extratags.pm - Useful Extensions for the CGI Module

# Copyright (C) 1999,2004 Stefan Hornburg

# Author: Stefan Hornburg (Racke) <racke@linuxia.de>
# Maintainer: Stefan Hornburg <racke@linuxia.de>
# Version: 0.03

# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2, or (at your option) any
# later version.

# This file is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this file; see the file COPYING.  If not, write to the Free
# Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

package CGI::Extratags;

use strict;
use vars qw($VERSION @ISA $AutoloadClass);
$VERSION = '0.03';

use URI::Escape;
use CGI;
$CGI::DefaultClass = __PACKAGE__;
$AutoloadClass = 'CGI';

@ISA = qw(CGI);

=head1 NAME

CGI::Extratags - Useful Extensions for the CGI Module

=head1 SYNOPSIS

  use CGI::Extratags;
  $cgi = new CGI::Extratags;

  print $cgi -> email ('racke@linuxia.de');

  print $cgi -> jump ('CONTACT', 'contact us');
  print $cgi -> mark ('CONTACT', $cgi -> h2 ('How to contact us'));

  print $cgi -> row ('Date', 18, 1, 1966);
  print $cgi -> recall ('Debian CD', artnum => '0-123456');

=head1 DESCRIPTION

CGI::Extratags adds several useful methods to the CGI class.

=cut

# Variables
# =========

my $maintainer_adr = 'racke@linuxia.de';

sub new ($$)
  {
	my $proto = shift;
	my $class = ref ($proto) || $proto;
	my $self = $class -> SUPER::new (@_);


	bless ($self, $class);
	return ($self);
  }

# --------------------------------------------------
# METHOD: email ADDRESS
#
# Produces HTML code for a link to an email ADDRESS.
# --------------------------------------------------

=over 4

=item email I<ADDRESS>

  print $cgi -> email ('racke@linuxia.de');

Produces HTML code for a link to an email I<ADDRESS>.

=back

=cut

sub email
  {
	my ($cgi, $address) = @_;

	$cgi -> a ({href=>"mailto:$address"}, "&lt;$address&gt;");
  }

# --------------------------------------------------
# METHOD: jump MARK TEXT
#
# Produces HTML code for a link pointing to a target
# within the current document.
# --------------------------------------------------

=over 4

=item jump I<MARK> I<TEXT>

  print $cgi -> jump ('CONTACT', 'contact us');

Produces HTML code for a link pointing to a target
within the current document.

=back

=cut

sub jump
  {
	my ($cgi, $mark, $text) = @_;

	$cgi -> a ({href => "#$mark"}, $text);
  }

# ----------------------
# METHOD: mark NAME TEXT
#
# Generates link target.
# ----------------------

=over 4

=item mark I<NAME> I<TEXT>

  print $cgi -> mark ('CONTACT', $cgi -> h2 ('How to contact us'));

Generates target I<NAME> for hyperlinks.

=back

=cut

sub mark
  {
	my ($cgi, $name, $text) = @_;

	$cgi -> a ({name => $name}, $text);
  }

# -------------------------------------------------------
# METHOD: row [ITEM ...]
#
# Creates table row with ITEM arguments as cell contents.
# -------------------------------------------------------

=over 4

=item row [I<ITEM> ...]

  print $cgi -> row ('Date', 18, 1, 1966);

Produces HTML code for a table row with I<ITEM> arguments as cell
contents.

=back

=cut

sub row
  {
	my $cgi = shift;
	
	$cgi -> Tr (map {ref($_) eq 'HASH' ? $_ : $cgi -> td ($_)} @_);
  }

# -----------------------------------------------------------------
# METHOD: recall TEXT [NAME [VALUE]] ...
#
# Produces a link to the script itself with the NAME/VALUE pairs as
# parameter list labeled with TEXT.
# -----------------------------------------------------------------

=over 4

=item recall I<TEXT> [I<NAME> [I<VALUE>]] ...

  foreach my $num (sort (keys %artmap))
    {
	print $cgi -> recall ($artmap{$num}, artnum => $num);
	print $cgi -> br;
    }

Produces a link to the script itself labeled with I<TEXT>. The
I<NAME>/I<VALUE> pairs will be passed as parameters.

=back

=cut

sub recall
  {
	my $cgi = shift; my $text = shift;
	my $query = ''; my @params; my $link;
	
	# generate query string
	while ($#_ >= 0)
	  {
		push (@params, uri_escape (shift) . '=' . uri_escape (shift));
	  }
	$query = '?' . join ('&', @params) if ($#params >= 0);

	# generate link
	$link = $cgi -> url (-relative => 1) || '';
	$cgi -> a ({href => $link . $query}, $text);
  }
		
1;
__END__

# Autoload methods go here, and are processed by the autosplit program.

=head1 AUTHOR

Stefan Hornburg, racke@linuxia.de

=head1 SEE ALSO

perl(1), URI::Escape(3), CGI(3).

=cut
