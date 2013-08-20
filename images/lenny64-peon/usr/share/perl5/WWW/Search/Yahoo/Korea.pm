# Korea.pm
# by Martin Thurn
# $Id: Korea.pm,v 1.4 2002/03/29 20:15:15 mthurn Exp $

=head1 NAME

WWW::Search::Yahoo::Korea - class for searching Yahoo! Korea

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('Yahoo::Korea');
  my $sQuery = WWW::Search::escape_query("Tokyo");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    print $oResult->url, "\n";

=head1 DESCRIPTION

This class is a Yahoo! Korea specialization of L<WWW::Search>.  It
handles making and interpreting searches on Yahoo! Korea
F<http://uk.yahoo.com>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 NOTES

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 BUGS

Please tell the maintainer if you find any!

=head1 TESTING

There are no tests defined for this module.

=head1 AUTHOR

C<WWW::Search::Yahoo> is maintained by Martin Thurn
(mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

If it''s not listed here, then it wasn''t a meaningful nor released revision.

=head2 2.02

minor pod update

=head2 2.01, 2001-03-30

First public release.

=cut

#####################################################################

package WWW::Search::Yahoo::Korea;

use Data::Dumper;  # for debugging only
use WWW::Search::Yahoo;

use strict;
use vars qw( @ISA $VERSION $MAINTAINER );
@ISA = qw( WWW::Search::Yahoo );

$VERSION = '2.02';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';


sub native_setup_search
  {
  my ($self, $sQuery, $rh) = @_;
  $self->{'_options'} = {
                         'p' => $sQuery,
                        };
  $rh->{'search_base_url'} = 'http://kr.search.yahoo.com';
  $rh->{'search_base_path'} = '/bin/search';
  return $self->SUPER::native_setup_search($sQuery, $rh);
  } # native_setup_search

1;

__END__
