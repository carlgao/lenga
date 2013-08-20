# DE.pm
# by Martin Thurn
# $Id: DE.pm,v 1.0 2003-07-27 21:57:08-04 kingpin Exp kingpin $

=head1 NAME

WWW::Search::AltaVista::DE - class for searching www.AltaVista.DE

=head1 SYNOPSIS

    require WWW::Search;
    $search = new WWW::Search('AltaVista::DE');

=head1 DESCRIPTION

This class handles making and interpreting AltaVista Germany searches
F<http://www.altavista.de>.

Details of AltaVista can be found at L<WWW::Search::AltaVista>.

This class exports no public interface; all interaction should
be done through WWW::Search objects.

=head1 AUTHOR

Martin Thurn C<mthurn@cpan.org>

=cut

#####################################################################

package WWW::Search::AltaVista::DE;

use WWW::Search::AltaVista;

use strict;
use vars qw( @ISA $VERSION );

@ISA = qw( WWW::Search::AltaVista );
$VERSION = sprintf("%d.%02d", q$Revision: 1.0 $ =~ /(\d+)\.(\d+)/o);

# private
sub native_setup_search
  {
  my $self = shift;
  my $sQuery = shift;
  if (!defined($self->{_options})) {
    $self->{_options} = {
                         'nbq' => '50',
                         'q' => $sQuery,
                         'search_host' => 'http://de.altavista.com',
                         'search_path' => '/web/results',
                        };
    };
  # Let AltaVista.pm finish up the hard work:
  return $self->SUPER::native_setup_search($sQuery, @_);
  } # native_setup_search

1;
