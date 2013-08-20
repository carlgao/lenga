# HotBot.pm
# by Wm. L. Scheding and Martin Thurn
# Copyright (C) 1996-1998 by USC/ISI
# $Id: HotBot.pm,v 1.75 2003/12/30 03:13:56 Daddy Exp $

=head1 NAME

WWW::Search::HotBot - backend for searching hotbot.lycos.com

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('HotBot');
  my $sQuery = WWW::Search::escape_query("+sushi restaurant +Columbus Ohio");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    { print $oResult->url, "\n"; }

=head1 DESCRIPTION

This class is a HotBot specialization of WWW::Search.
It handles making and interpreting HotBot searches
F<http://www.hotbot.com> via the Inktomi index.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 BUGS

Please tell the author if you find any!

=head1 AUTHOR

As of 1998-02-02, C<WWW::Search::HotBot> is maintained by Martin Thurn
(mthurn@cpan.org).

C<WWW::Search::HotBot> was originally written by Wm. L. Scheding,
based on C<WWW::Search::AltaVista>.

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

If it is not listed here, then it was not a meaningful nor released revision.

=head2 2.28, 2003-02-20

MAJOR overhaul for new www.hotbot.com

=head2 2.27, 2002-07-11

FIX for mangled "sponsored links" (by ignoring them!)

=head2 2.25, 2001-12-17

FIX for new URL output format with date; delete unused code; get next page of results

=head2 2.24, 2001-10

Massive re-write using new website parameters and HTML::TreeBuilder

=head2 2.23, 2001-07-19

Tweak pattern for result-count; set agent_name to something that works

=head2 2.21, 2000-12-11

new URL for advanced search

=head2 2.19, 2000-10-11

added AM1=MC to all URLs in GUI mode (hotbot.com seems to "randomly"
add this if you search manually at their site)

=head2 2.18, 2000-06-26

fix for only one page of gui results; and "next" link in new place

=head2 2.17, 2000-05-24

was still missing first URL of non-gui(?) results!

=head2 2.16, 2000-05-17

was missing first URL of gui results

=head2 2.15, 2000-04-03

fixed gui_query()

=head2 2.14, 2000-02-01

testing now uses WWW::Search::Test module

=head2 2.13, 2000-01-31

bugfix: was missing title

=head2 2.12, 2000-01-19

new function gui_query(), and handle output from it

=head2 2.10, 1999-12-22

handle new result format

=head2 2.09, 1999-12-15

handle new result count format

=head2 2.08, 1999-12-10

handle new output format

=head2 2.07, 1999-11-12

BUGFIX for domain-limited URL parsing (thanks to Leon Brocard)

=head2 2.06, 1999-10-18

www.hotbot.com changed their output format slightly;
now uses strip_tags() on title and description

=head2 2.05, 1999-10-05

now uses hash_to_cgi_string(); new test cases

=head2 2.03, 1999-09-28

BUGFIX: was missing the "Next page" link sometimes.

=head2 2.02, 1999-08-17

Now is able to parse "URL-only" format (i.e. {'DE' => 0}) and "brief
description" format (i.e. {'DE' => 1}) if the user so desires.

=head2 1.34, 1999-07-01

New test cases.

=head2 1.32, 1999-06-20

Now unescapes the URLs before returning them.

=head2 1.31, 1999-06-11

www.hotbot.com changed their output format ever so slightly.  (Thanks
to Jim jsmyser at bigfoot.com for pointing it out)

=head2 1.30, 1999-04-12

BUG FIX: results for domain-limited search were not parsed.  (Thanks to
Christopher York yorkc at ccwf.cc.utexas.edu for pointing it out)

=head2 1.29, 1999-02-22

www.hotbot.com changed their output format.  (Thanks to Tim Chklovski
timc at mit.edu for pointing it out)

=head2 1.27, 1998-11-06

HotBot changed their output format(?).
HotBot.pm now uses hotbot.com's text-only search results format.
Minor documentation changes.

=head2 1.25, 1998-09-11

HotBot changed their output format ever so slightly.
Documentation added for all known HotBot query options!

=head2 1.23

Better documentation for boolean queries.  (Thanks to Jason Titus jason_titus at odsnet.com)

=head2 1.22

www.hotbot.com changed their output format.

=head2 1.21

www.hotbot.com changed their output format.

=head2 1.17

www.hotbot.com changed their search script location and output format on 1998-05-21.
Also, as many as 6 fields of each SearchResult are now filled in.

=head2 1.13

Fixed the maximum_to_retrieve off-by-one problem.
Updated test cases.

=head2 1.12

www.hotbot.com does not do truncation. Therefore, if the query
contains truncation characters (i.e. '*' at end of words), they are
simply deleted before the query is sent to www.hotbot.com.

=head2 1.11, 1998-02-05

Fixed and revamped by Martin Thurn.

=cut

#####################################################################

package WWW::Search::HotBot;

require Exporter;
@EXPORT = qw( );
@EXPORT_OK = qw( );
@ISA = qw( WWW::Search Exporter );

$VERSION = '2.29';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

use Carp ();
use WWW::Search qw( generic_option strip_tags );
use WWW::Search::Result;
use URI::Escape;

use strict;

# private
sub native_setup_search
  {
  my ($self, $native_query, $native_options_ref) = @_;

  $self->{_debug} = $native_options_ref->{'search_debug'};
  $self->{_debug} = 2 if ($native_options_ref->{'search_parse_debug'});
  $self->{_debug} ||= 0;

  # Why waste time sending so many queries?  Do a whole lot all at once!
  # 500 results take  70 seconds at 100 per page
  # 500 results take 234 seconds at  10 per page
  my $DEFAULT_HITS_PER_PAGE = 100;
  # $DEFAULT_HITS_PER_PAGE = 10 if $self->{_debug};
  $self->{'_hits_per_page'} = $DEFAULT_HITS_PER_PAGE;
  # $self->timeout(120);  # HotBot used to be notoriously slow

  # As of 2002-02, hotbot.com refuses robots:
  $self->user_agent('non-robot');
  # hotbot.pm seems to send a DIFFERENT page format if the client is
  # MSIE.  So, make sure they DON'T think we're MSIE!  Added by Martin
  # Thurn 2001-07-19.
  $self->{'agent_name'} = 'Mozilla/4.76';
  $self->{_next_to_retrieve} = 0;
  $self->{'_num_hits'} = 0;
  if (!defined($self->{_options}))
    {
    $self->{_options} = {
                         'search_url' => 'http://www.hotbot.com/default.asp',
                         'prov' => 'Inktomi',
                         'query' => $native_query,
                         'recordcount' => $self->{_hits_per_page},
                        };
    } # if
  my $options_ref = $self->{_options};
  if (defined($native_options_ref))
    {
    # Copy in new options.
    foreach (keys %$native_options_ref)
      {
      $options_ref->{$_} = $native_options_ref->{$_};
      } # foreach
    } # if
  # Finally, figure out the url.
  $self->{_next_url} = $self->{_options}{'search_url'} .'?'. $self->hash_to_cgi_string($options_ref);
  } # native_setup_search


sub preprocess_results_page_OFF
  {
  my $self = shift;
  my $s = shift;
  print STDERR "\n$s\n";
  return $s;
  } # preprocess_results_page


sub parse_tree
  {
  my $self = shift;
  my $oTree = shift;
  my $hits_found = 0;
  my @aoFONT = $oTree->look_down(
                                 '_tag' => 'div',
                                 'class' => 'subt',
                                );
 FONT_TAG:
  foreach my $oBQ (@aoFONT)
    {
    if (ref $oBQ)
      {
      my $sBQ = $oBQ->as_text;
      print STDERR " +   BQ == $sBQ\n" if 2 <= $self->{_debug};
      if ($sBQ =~ m!Results\s+\d+\s+-\s+\d+\s+of\s+([0-9,]+)!i)
        {
        my $sCount = $1;
        print STDERR " +     raw    count == $sCount\n" if 3 <= $self->{_debug};
        $sCount =~ s!,!!g;
        print STDERR " +     cooked count == $sCount\n" if 3 <= $self->{_debug};
        $self->approximate_result_count($sCount);
        last FONT_TAG;
        } # if
      } # if
    } # foreach
  my @aoP = $oTree->look_down(
                              '_tag' => 'p',
                              'class' => 'res',
                             );
 P_TAG:
  foreach my $oP (@aoP)
    {
    my ($sDesc, $sDate, $sSize, $sScore);
    $sDesc = '';
    next P_TAG unless ref $oP;
    print STDERR " +   try oP ===", $oP->as_text, "===\n" if 2 <= $self->{_debug};
    my $oA = $oP->look_down('_tag', 'a');
    next P_TAG unless (ref $oA);
    my $oSPANurl = $oP->look_down('_tag' => 'span',
                                  'class' => 'grn',
                                 );
    next P_TAG unless (ref $oSPANurl);
    my $sTitle = $oA->as_text;
    print STDERR " +   found title ===$sTitle===\n" if 2 <= $self->{_debug};
    my $sURL = $self->absurl($self->{_prev_url}, $oSPANurl->as_text);
    print STDERR " +   found url ===$sURL===\n" if 2 <= $self->{_debug};
    my @aoSPAN = $oP->look_down(
                                 '_tag' => 'span',
                                 'class' => 'sub',
                                );
    my $oSPAN = shift(@aoSPAN);
    if (ref $oSPAN)
      {
      $sDate = $oSPAN->as_text;
      $sDate =~ s!\A\s+-\s+!!;
      $oSPAN->detach;
      $oSPAN->delete;
      } # if
    $oSPAN = shift(@aoSPAN);
    if (ref $oSPAN)
      {
      $sSize = $oSPAN->as_text;
      $sSize =~ s!\A\s+-\s+!!;
      $sSize =~ s!\s+\Z!!;
      $oSPAN->detach;
      $oSPAN->delete;
      } # if
    # Delete all remaining <SPAN>s:
    @aoSPAN = $oP->look_down(
                             '_tag' => 'span',
                            );
    foreach my $oSPAN (@aoSPAN)
      {
      next unless ref $oSPAN;
      $oSPAN->detach;
      $oSPAN->delete;
      } # foreach
    my $s = $oP->as_HTML;
    if ($s =~ m/<!--\s*REL\s(\d+%)\s*-->/)
      {
      $sScore = $1;
      } # if
    $oA->detach;
    $oA->delete;
    $sDesc = $oP->as_text;

    my $hit = new WWW::Search::Result;
    $hit->add_url($sURL);
    $hit->title($sTitle);
    $hit->description(&WWW::Search::strip_tags($sDesc));
    $hit->change_date($sDate);
    $hit->size($sSize);
    $hit->score($sScore);
    push(@{$self->{cache}}, $hit);
    $self->{'_num_hits'}++;
    $hits_found++;
    # Make it faster to find the 'next' link(?):
    $oP->detach;
    $oP->delete;
    } # foreach $oP
  # Find the next link, if any:
  my @aoA = $oTree->look_down('_tag', 'a',
                              sub { $_[0]->as_text =~ m!\A[\ \t\r\n]+Next[\ \t\r\n]*\Z!s } );
 A_TAG:
  # We want the last "next" link on the page:
  my $oA = $aoA[-1];
  # foreach my $oA (@aoA)
    {
    next unless ref $oA;
    # if ($oA->as_text eq 'next')
      {
      print STDERR " +   oAnext is ===", $oA->as_HTML, "===\n" if 2 <= $self->{_debug};
      $self->{_next_url} = $self->absurl($self->{'_prev_url'}, $oA->attr('href'));
      # last A_TAG;
      } # if
    } # foreach

 SKIP_NEXT_LINK:

  return $hits_found;
  } # parse_tree

1;

__END__

2003-02 basic search results:

http://www.hotbot.com/default.asp?prov=Inktomi&query=Martin+Thurn&recordcount=100

2002-07 advanced search results:

http://hotbot.lycos.com/default.asp?lpv=1&query=Galoob&first=1&page=more&ca=dh&loc=mlink_w&descriptiontype=2&dateday=1&datemonth=1&daterelation=newer&dateyear=2000&matchmode=any&nummod=2&recordcount=100&sitegroup=1&cobrand=undefined
http://hotbot.lycos.com/default.asp?lpv=1&query=Galoob&first=1&page=more&ca=dh&descriptiontype=2&matchmode=any&recordcount=100

2002-07 gui query results:

http://hotbot.lycos.com/?query=Star+Wars&cobrand=&matchmode=all&datedelta=0&language=any&recordcount=10&descriptiontype=2&modsign1=MC&dateoption=within&placeselection=georegion

2000-10 text-only advanced search results:

http://hotbot.lycos.com/text/default.asp?matchmode=any&query=Martin+Thurn&recordcount=100&descriptiontype=2&modsign0=must&modtype0=words&modwords0=&modsign1=must&modtype1=words&modwords1=&dateoption=within&datedelta=0&daterelation=newer&datemonth=1&DD=1&dateyear=2000&language=any&extension=&domain=&placeselection=georegion&georegion=all&sitegroup=1&pagetype=A&PD=&act.query=1&search=SEARCH&NUMMOD=2

http://hotbot.lycos.com/text/default.asp?DD=1&NUMMOD=2&PD=&act.query=1&datedelta=0&datemonth=1&dateoption=within&daterelation=newer&dateyear=2000&descriptiontype=2&domain=&extension=&georegion=all&language=any&matchmode=any&modsign0=must&modsign1=must&modtype0=words&modtype1=words&modwords0=&modwords1=&pagetype=A&placeselection=georegion&query=Martin+Thurn&recordcount=100&search=SEARCH&sitegroup=1

2000-10 graphics-version advanced search results:

http://hotbot.lycos.com/?query=martin+thurn&cobrand=&act.query=1&matchmode=any&language=any&modsign0=must&modtype0=words&modwords0=&modsign1=must&modtype1=words&modwords1=&NUMMOD=2&dateoption=within&datedelta=0&daterelation=newer&datemonth=1&DD=1&dateyear=2000&extension=&placeselection=georegion&georegion=all&domain=&pagetype=A&PD=&recordcount=10&descriptiontype=2&SUBMIT=SEARCH

