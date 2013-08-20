
=head1 NAME

WWW::Search::AltaVista::Web - deprecated, just use WWW::Search::AltaVista

=head1 SYNOPSIS

  use WWW::Search;
  $search = new WWW::Search('AltaVista');

=head1 DESCRIPTION

Details of searching AltaVista.com can be found at
L<WWW::Search::AltaVista>.

=cut

package WWW::Search::AltaVista::Web;

use WWW::Search::AltaVista;
@ISA = qw(WWW::Search::AltaVista);

1;

__END__
