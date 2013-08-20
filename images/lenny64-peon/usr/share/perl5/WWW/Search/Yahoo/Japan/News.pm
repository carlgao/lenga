# $Id: News.pm,v 1.4 2002/03/29 20:14:56 mthurn Exp mthurn $

=head1 NAME

WWW::Search::Yahoo::Japan::News - class for searching News on Yahoo Japan (in Japanese)

=head1 SYNOPSIS

  use Jcode;
  use WWW::Search;
  my $oSearch = new WWW::Search('Yahoo::Japan::News');
  my $sQuery = WWW::Search::escape_query(Jcode->new("ÎÁÍý¤ÎÅ´¿Í")->euc);
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    print $oResult->url, "\n";

=head1 DESCRIPTION

This class is a Yahoo Japan News specialization of L<WWW::Search>.  It
handles making and interpreting searches of Yahoo News in Japanese
F<http://headlines.yahoo.co.jp>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 NOTES

Query string must be in EUC encoding, and then escaped with
WWW::Search::escape_query().

If you have multiple query terms, put an ASCII space character in
between all of them.

Yahoo Japan does an AND of all query terms.
There is no way to change this.

In the results, description will be in EUC encoding (I think).

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 BUGS

Please tell the maintainer if you find any!

=head1 TESTING

This module adheres to the C<WWW::Search> test suite mechanism.

=head1 AUTHOR

Martin Thurn (mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

If it''s not listed here, then it wasn''t a meaningful nor released revision.

=head2 2.02, 2001-09-13

bugfix, apparently 2.01 could not load at all!?!

=head2 2.01, 2001-09-07

First release.

=cut

package WWW::Search::Yahoo::Japan::News;

@ISA = qw( WWW::Search WWW::Search::Yahoo );

$VERSION = '2.03';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

use Data::Dumper; # for debugging only
use WWW::Search qw( strip_tags );
use WWW::SearchResult;
use WWW::Search::Yahoo;

use strict;

sub native_setup_search
  {
  my ($self, $sQuery) = (shift, shift);
  $self->{'_options'} = {
                         'p' => $sQuery,
                        };
  return WWW::Search::Yahoo::native_setup_search($self, $sQuery,
                                            {
                                             'search_base_url' => 'http://nsearch.yahoo.co.jp',
                                             'search_base_path' => '/bin/nsearch',
                                            },
                                          @_);
  } # native_setup_search

# sub native_retrieve_some() is inherited from WWW::Search::Yahoo

# When I ran queries with Netscape, yahoo gave me EUC encoding.  So
# that's what I use in the regexen below.  Thanks to Emacs 20.7, I can
# just type it right in the code!

sub parse_tree
  {
  my $self = shift;
  my $tree = shift;
  my $hits_found = 0;
  # The hit count is in a <small> tag:
  my @aoSMALL = $tree->look_down('_tag', 'small');
 SMALL_TAG:
  foreach my $oSMALL (@aoSMALL)
    {
    next unless ref $oSMALL;
    my $sSmall = $oSMALL->as_text;
    if ($sSmall =~ m!\241\312(\d+)·ïÃæ!)
      {
      my $iCount = $1;
      $self->approximate_result_count($iCount);
      print STDERR " +   num results = $iCount\n" if $self->{_debug};
      last SMALL_TAG;
      } # if
    } # foreach

  # The next link is in an <a> tag:
  my @aoANEXT = $tree->look_down('_tag', 'a');
 ANEXT_TAG:
  foreach my $oANEXT (@aoANEXT)
    {
    next unless ref $oANEXT;
    my $sAnext = $oANEXT->as_text;
    if ($sAnext =~ m!¼¡¤Î\d+·ï!)
      {
      $self->{_next_url} = $self->absurl($self->{'_prev_url'}, $oANEXT->attr('href'));
      print STDERR " +   next link = $self->{_next_url}\n" if $self->{_debug};
      last ANEXT_TAG;
      } # if
    } # foreach

  # Each result is in a <P>, but HTML::Parser can not parse those <P>s
  # because the first one is mal-formed (contains a <BASE> tag which
  # is not legal inside a <P>).  So, just look for <A> with a <SMALL>
  # sibling.
  my @aoA = $tree->look_down('_tag', 'a');
 A_TAG:
  foreach my $oA (@aoA)
    {
    next A_TAG unless ref $oA;
    if (2 <= $self->{_debug})
      {
      my $s = $oA->as_HTML;
      print STDERR " +   A ===$s===\n";
      } # if debug
    # Result <A> must have a <SMALL> sibling with a <BR> in between:
    my $iSawBR = 0;
    my $oSMALL;
    my @aoSib = $oA->right;
 SIBLING:
    foreach my $oSib (@aoSib)
      {
      # Sanity check:
      next SIBLING unless defined $oSib;
      print STDERR " +     try oSMALL ==$oSib==\n" if (3 <= $self->{_debug});
      # Skip over plain text elements:
      next SIBLING unless ref $oSib;
      print STDERR " +         oSMALL ==", $oSib->as_HTML, "==\n" if (3 <= $self->{_debug});
      if ($oSib->tag eq 'br')
        {
        $iSawBR = 1;
        } # if
      if ($oSib->tag eq 'small')
        {
        $oSMALL = $oSib;
        last SIBLING;
        } # if
      } # foreach
    # Does this <A> have a <BR> sibling?
    next A_TAG unless $iSawBR;
    # Does this <A> have a <SMALL> sibling?
    print STDERR " +   after loop, oSMALL ==$oSMALL==\n" if (3 <= $self->{_debug});
    next A_TAG unless ref $oSMALL;
    print STDERR " +   after loop, oSMALL ==", $oSMALL->as_HTML, "==\n" if (3 <= $self->{_debug});
    next A_TAG unless ($oSMALL->tag eq 'small');
    if (2 <= $self->{_debug})
      {
      my $s = $oSMALL->as_HTML;
      print STDERR " +   SMALL ===$s===\n\n";
      } # if debug
    my $sURL = $oA->attr('href') || '';
    next A_TAG unless $sURL ne '';
    my $sTitle = $oA->as_text;
    my $sDesc = &strip_tags($oSMALL->as_text);
    my $hit = new WWW::SearchResult;
    $hit->add_url($sURL);
    $hit->title($sTitle);
    $hit->description($sDesc);
    push(@{$self->{cache}}, $hit);
    $self->{'_num_hits'}++;
    $hits_found++;
    } # foreach
  print STDERR " +   found $hits_found results on this page\n" if $self->{_debug};
  return $hits_found;
  } # parse_tree

1;

__END__
