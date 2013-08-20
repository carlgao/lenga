
# $Id: Advanced.pm,v 1.7 2002/11/01 15:08:21 mthurn Exp $

=head1 NAME

WWW::Search::Yahoo::News::Advanced - class for searching Yahoo! News
using the "advanced" interface

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('Yahoo::News::Advanced');
  my $sQuery = WWW::Search::escape_query("George Lucas");
  $oSearch->date_from('2001-05-05');
  $oSearch->date_to(  '2001-07-05');
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    print $oResult->url, "\n";

=head1 DESCRIPTION

This class is a Yahoo! News specialization of L<WWW::Search>.  It
handles making and interpreting searches on Yahoo! News
F<http://search.news.yahoo.com> using the Advanced search interface.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 NOTES

This backend supports narrowing the search by date-range.
Use date_from() and date_to() to set the endpoints of the desired date range.
You can use any date format supported by the Date::Manip module.

If either date endpoint is not set explicitly,
it will search with an appropriately open-ended date range.

NOTE that Yahoo only keeps the last 90 days worth of news in its index.

ALSO NOTE that Yahoo will return an ERROR if date_from() is set to
anything prior to Jan. 1 1999.  This backend does NOT check for that.

News.yahoo.com dies if the unescaped query is longer than 485
characters or so.  This backend does NOT check for that.

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 BUGS

Please tell the maintainer if you find any!

=head1 TESTING

There are no tests defined for this module.

=head1 AUTHOR

C<WWW::Search::Yahoo::News::Advanced> is maintained by Martin Thurn
(mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

If it''s not listed here, then it wasn''t a meaningful nor released revision.

=head2 2.04, 2002-10-31

overhaul for new webpage format

=head2 2.01, 2001-07-16

First public release.

=cut

#####################################################################

package WWW::Search::Yahoo::News::Advanced;

use Data::Dumper;  # for debugging only
use Date::Manip;
use WWW::Search qw( strip_tags );
use WWW::Search::Result;
use WWW::Search::Yahoo;

use strict;
use vars qw( @ISA $VERSION $MAINTAINER );
@ISA = qw( WWW::Search::Yahoo );

$VERSION = '2.04';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

sub native_setup_search
  {
  my ($self, $sQuery, $rh) = @_;
  # print STDERR " +   in UK::native_setup_search, rh is ", Dumper($rh);
  my $sDateFrom = $self->date_from || '';
  my $sDateTo = $self->date_to || '';
  if ($sDateFrom ne '')
    {
    # User specified the beginning date.
    $sDateFrom = &UnixDate(&ParseDate($sDateFrom), '%m/%d/%y');
    }
  else
    {
    # User did not specify the beginning date.  Set it to the distant
    # past.  Yahoo.com barfs if it gets a date earlier than 1999,
    # though.
    $sDateFrom = &UnixDate(&ParseDate('1999-01-01'), '%m/%d/%y');
    }
  if ($sDateTo ne '')
    {
    # User specified the ending date.
    $sDateTo = &UnixDate(&ParseDate($sDateTo), '%m/%d/%y');
    }
  else
    {
    # User did not specify the ending date.  Set it to the future:
    $sDateTo = &UnixDate(&ParseDate('tomorrow'), '%m/%d/%y');
    }
  $self->{'_options'} = {
                         '3' => "$sDateFrom-$sDateTo",
                         'n' => 100,  # 10 for testing, 100 for release
                         'o' => 'o',  # OR of all words
                         'p' => $sQuery,
                         # I want to sort by descending relevance, but
                         # yahoo.com is broken.  the 's' parameter in
                         # the URL has no meaningful effect.

                         # 's' => '-s',  # sort order
                        };
  $rh->{'search_base_url'} = 'http://search.news.yahoo.com';
  $rh->{'search_base_path'} = '/search/news';
  # print STDERR " +   Yahoo::UK::native_setup_search() is calling SUPER::native_setup_search()...\n";
  return $self->SUPER::native_setup_search($sQuery, $rh);
  } # native_setup_search


sub preprocess_results_page
  {
  my $self = shift;
  # Confound it!  All the results are in a <P> except the first one!
  my $s = shift;
  $s =~ s!</font></td></tr></table>!</table> <P>!g;
  return $s;
  } # preprocess_results_page


sub parse_tree
  {
  my $self = shift;
  my $tree = shift;
  my $hits_found = 0;
  my @aoFONTcount = $tree->look_down('_tag', 'font',
                                     'face' => 'arial',
                                     'size' => '-1',
                                    );
 FONTcount_TAG:
  foreach my $oFONT (@aoFONTcount)
    {
    my $s = $oFONT->as_text;
    print STDERR " + FONTcount == ", $oFONT->as_HTML if 2 <= $self->{_debug};
    # print STDERR " +   TEXT == ", $s, "\n" if 2 <= $self->{_debug};
    if ($s =~ m!\d+\s*-\s*\d+\s+of\s+(\d+)!)
      {
      my $iCount = $1;
      # print STDERR " +   found number $iCount\n" if 2 <= $self->{_debug};
      $self->approximate_result_count($iCount);
      last FONTcount_TAG;
      } # if
    } # foreach FONT_TAG

  # Each URL result is in a <FONT size=-1> tag:
  # <font face="arial" size="-1"><a href="http://story.news.yahoo.com/news?tmpl=story&amp;u=/ap/20021030/ap_on_en_mo/neeson_royal_2">Neeson Nervous About Royal Honor</a></font> <font face="arial" size="-2">(AP)</font><br><font face="arial" size="-1"> ...&quot;<b>Star Wars</b>: Episode I: The Phantom Menace.... <br>- <small><i> Oct 30 7:09 AM ET </i></small> </font>
  my @aoFONT = $tree->look_down('_tag' => 'font',
                                'size' => '-1',
                               );
FONT_TAG:
  foreach my $oFONT (@aoFONT)
    {
    my $sPrice = '';
    printf STDERR "\n + FONT == %s", $oFONT->as_HTML if 2 <= $self->{_debug};
    my $oAtitle = $oFONT->look_down('_tag', 'a');
    next FONT_TAG unless ref($oAtitle);
    my $sURL = $oAtitle->attr('href');
    next FONT_TAG unless defined($sURL);
    next FONT_TAG unless ($sURL ne '');
    next FONT_TAG if $sURL =~ m!search\.yahoo\.com!;
    print STDERR " +   URL   == $sURL\n" if 2 <= $self->{_debug};
    # In order to make it easier to parse, make sure everything is an object!
    $oFONT->parent->objectify_text;
    # Siblings contain more info.
    my @aoSib = $oFONT->right;
    # Next tag contains source:
    my $oFONTsource = &skip_text_elements(\@aoSib);
    # Bail if there are no more siblings:
    next FONT_TAG unless ref($oFONTsource);
    # Look for price of premium article:
    if (defined($oFONTsource->attr('color')) && ($oFONTsource->attr('color') eq 'red'))
      {
      $oFONTsource->deobjectify_text;
      $sPrice = $oFONTsource->as_text;
      printf STDERR " +   FONTprice == %s", $oFONTsource->as_HTML if 2 <= $self->{_debug};
      $oFONTsource = &skip_text_elements(\@aoSib);
      } # if
    printf STDERR " +   FONTsource == %s", $oFONTsource->as_HTML if 2 <= $self->{_debug};
    my $oBR = &skip_text_elements(\@aoSib);
    next FONT_TAG unless ref($oBR);
    printf STDERR " +   BR == %s", $oBR->as_HTML if 2 <= $self->{_debug};
    my $oFONTdesc = &skip_text_elements(\@aoSib);
    next FONT_TAG unless ref($oFONTdesc);
    printf STDERR " +   FONTdesc == %s", $oFONTdesc->as_HTML if 2 <= $self->{_debug};

    # The only <i> tag contains the date...
    my $oI = $oFONTdesc->look_down('_tag', 'i');
    # ...and we only need to look at <P> which contains a date:
    next FONT_TAG unless ref($oI);
    printf STDERR " +   I == %s", $oI->as_HTML if 2 <= $self->{_debug};
    $oI->deobjectify_text;
    my $sDate = $oI->as_text;
    # delete this <I> tag so the description is easy to get:
    $oI->detach;
    $oI->delete;

    # The (remaining) text of the P is the description:
    $oFONTdesc->deobjectify_text;
    my $sDesc = &strip_tags($oFONTdesc->as_text);
    # Delete junk off end of description:
    $sDesc =~ s!\s+-\s+\Z!!;
    # Add price if present:
    $sDesc .= qq{ [$sPrice]} if ($sPrice ne '');
    print STDERR " +   DESC  == $sDesc\n" if 2 <= $self->{_debug};
    $oAtitle->deobjectify_text;
    my $sTitle = $oAtitle->as_text;
    print STDERR " +   TITLE == $sTitle\n" if 2 <= $self->{_debug};
    my $hit = new WWW::Search::Result;
    $hit->add_url($sURL);
    $hit->title($sTitle);
    $hit->description($sDesc);
    $hit->change_date($sDate);
    push(@{$self->{cache}}, $hit);
    $self->{'_num_hits'}++;
    $hits_found++;
    # Delete this <FONT> (to make it quicker to find the "Next" link)
    $oFONT->detach;
    $oFONT->delete;
    } # foreach oFONT

  $tree->deobjectify_text;
  # The "next" link is a plain old <A>:
  my @aoA = $tree->look_down('_tag', 'a');
A_TAG:
  foreach my $oA (@aoA)
    {
    printf STDERR " + A == %s\n", $oA->as_HTML if 2 <= $self->{_debug};
    # <a href="http://search.news.yahoo.com/search/news?p=Japan&amp;b=21"><b>Next 20 &gt;</b></a>
    if ($oA->as_text =~ m!Next\s+\d+\s+!i)
      {
      $self->{_next_url} = $HTTP::URI_CLASS->new_abs($oA->attr('href'), $self->{'_prev_url'});
      last A_TAG;
      } # if
    } # foreach $oA
  $tree->delete;
  return $hits_found;
  } # parse_tree


sub skip_text_elements
  {
  my $ra = shift;
  my $o;
  # print STDERR " +     skip_text_elements\n";
  while (1)
    {
    $o = shift(@$ra);
    # Bail if we run out of arguments:
    last unless ref($o);
    # print STDERR (" +     consider o==%s", $o->as_HTML);
    # All done if we get something not text:
    last if ($o->tag ne '~text');
    } # while
  return $o;
  } # skip_text_elements

1;

__END__

http://search.news.yahoo.com/search/news?p=george+lucas&s=&n=10&o=&2=&3=05/05/01-05/15/01
