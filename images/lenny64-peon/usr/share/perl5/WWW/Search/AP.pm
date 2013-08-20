
# $Id: AP.pm,v 1.3 2003-12-13 16:13:47-05 kingpin Exp kingpin $

=head1 NAME

WWW::Search::AP - backend for searching AP News at www.washingtonpost.com

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('AP');
  my $sQuery = WWW::Search::escape_query("japan prime minister");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    { print $oResult->url, "\n"; }

=head1 DESCRIPTION

This class is a specialization of WWW::Search.  It handles making and
interpreting searches on news at The AP section of The Washington Post
F<http://www.washtech.com>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 NOTES

=head1 BUGS

Please tell the author if you find any!

=head1 AUTHOR

C<WWW::Search::AP> is maintained by Martin Thurn
(mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

If it is not listed here, then it was not a meaningful nor released revision.

=head2 2.01, 2002-03-12

First public release.

=cut

#####################################################################

package WWW::Search::AP;

use strict;
use vars qw( @ISA $VERSION $MAINTAINER );

use WWW::Search::WashPost;

@ISA = qw( WWW::Search::WashPost );

$VERSION = '2.01';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

# private
sub native_setup_search
  {
  my ($self, $sQuery, $rhOptions) = @_;
  $self->{_options} = {
                       'search_url' => 'http://sitesearch.washingtonpost.com/cgi-bin/search99.pl',
                       'searchsection' => 'news',
                       'searchtext' => $sQuery,
                       'searchdatabase' => 'ap',
                      };
  $self->SUPER::native_setup_search($sQuery, $rhOptions);
  } # native_setup_search


1;

__END__

http://www.washingtonpost.com/cgi-bin/search99.pl?searchdatabase=serf&serf_ap=on&ap=on&description=microsoft+eu+concessions&headline=&_u.16=14

http://sitesearch.washingtonpost.com/cgi-bin/search99.pl?searchdatabase=serf&serf_ap=on&ap=on&description=%22World+Cup%22&headline=&_u.16=14
