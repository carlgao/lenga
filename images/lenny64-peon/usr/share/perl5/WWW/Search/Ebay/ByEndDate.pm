# Ebay/ByEndDate.pm
# by Martin Thurn
# $Id: ByEndDate.pm,v 1.2 2003-12-06 20:12:42-05 kingpin Exp kingpin $

=head1 NAME

WWW::Search::Ebay::ByEndDate - backend for searching www.ebay.com, with results sorted with "items ending first"

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('Ebay::ByEndDate');
  my $sQuery = WWW::Search::escape_query("C-10 carded Yakface");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    { print $oResult->url, "\n"; }

=head1 DESCRIPTION

This class is a Ebay specialization of WWW::Search.
It handles making and interpreting Ebay searches
F<http://www.ebay.com>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 NOTES

The search is done against CURRENT running auctions only.

The query is applied to TITLES only.

The results are ordered auctions ending soon first (order of
increasing auction ending date).

In the resulting WWW::Search::Result objects, the description field
consists of a human-readable combination (joined with semicolon-space)
of the Item Number; number of bids; and high bid amount (or starting
bid amount).

In the WWW::Search::Result objects, the change_date field contains the
auction ending date & time exactly as returned by ebay.com; this can
have values like "in 12 mins" or "5d 3h 15m".

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 CAVEATS

=head1 BUGS

Please tell the author if you find any!

=head1 AUTHOR

C<WWW::Search::Ebay::ByEndDate> was written by Martin Thurn
(mthurn@cpan.org).

C<WWW::Search::Ebay::ByEndDate> is maintained by Martin Thurn
(mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

=head2 2.02

Fixed hash vs. array bug?

=head2 2.01

First publicly-released version.

=cut

#####################################################################

package WWW::Search::Ebay::ByEndDate;

use Carp;
use WWW::Search::Ebay;
@ISA = qw( WWW::Search::Ebay );

$VERSION = '2.02';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

# private
sub native_setup_search
  {
  my ($self, $native_query, $rhOptsArg) = @_;
  $rhOptsArg ||= {};
  unless (ref($rhOptsArg) eq 'HASH')
    {
    carp " --- second argument to native_setup_search should be hashref, not arrayref";
    return undef;
    } # unless
  $rhOptsArg->{'SortProperty'} = 'MetaEndSort';
  return $self->SUPER::native_setup_search($native_query, $rhOptsArg);
  } # native_setup_search

# Enforce sorting by end date, even if Ebay is returning it in a
# different order.  Calls parse_tree() of the base class, and then
# reshuffles its 'cache' results.  Code contributed by Mike Schilli.

sub parse_tree
  {
  my ($self, @args) = @_;
  my $hits = $self->SUPER::parse_tree(@args);
  $self->{cache} = [sort { minutes($a->change_date()) <=>
                           minutes($b->change_date()) }
                    @{$self->{cache}}];
  return $hits;
  } # parse_tree

sub minutes
  {
  my ($s) = @_;
  my $min = 0;
  $min += 60*24*$1 if $s =~ /(\d+)[dT]/;
  $min += 60*$1 if $s =~ /(\d+)[hS]/;
  $min += $1 if $s =~ /(\d+)[mM]/;
  return $min;
  } # minutes

1;

__END__
