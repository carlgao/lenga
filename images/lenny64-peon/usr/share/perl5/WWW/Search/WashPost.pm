# WashPost.pm
# by Martin Thurn
# Copyright (C) 1996-1998 by USC/ISI
# $Id: WashPost.pm,v 2.6 2003-12-13 16:13:25-05 kingpin Exp kingpin $

=head1 NAME

WWW::Search::WashPost - backend for searching www.washingtonpost.com

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('WashPost');
  my $sQuery = WWW::Search::escape_query("japan prime minister");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    { print $oResult->url, "\n"; }

=head1 DESCRIPTION

This class is a specialization of WWW::Search.  It handles making and
interpreting searches on news at The Washington Post
F<http://www.washingtonpost.com>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 CAVEATS

=head1 BUGS

Please tell the author if you find any!

=head1 AUTHOR

C<WWW::Search::WashPost> is maintained by Martin Thurn
(mthurn@cpan.org).

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

see ChangeLog

=cut

#####################################################################

package WWW::Search::WashPost;

use strict;
use vars qw( @ISA $VERSION $MAINTAINER );

@ISA = qw( WWW::Search );

$VERSION = sprintf("%d.%02d", q$Revision: 2.6 $ =~ /(\d+)\.(\d+)/o);
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

use WWW::Search;
use WWW::SearchResult;
use URI;

# private
sub native_setup_search
  {
  my ($self, $sQuery, $native_options_ref) = @_;

  $self->{_debug} = $native_options_ref->{'search_debug'};
  $self->{_debug} = 2 if ($native_options_ref->{'search_parse_debug'});
  $self->{_debug} ||= 0;

  # washingtonpost.com does not let us change this:
  my $DEFAULT_HITS_PER_PAGE = 10;
  $self->{'_hits_per_page'} = $DEFAULT_HITS_PER_PAGE;
  # $self->timeout(120);  # use this if website is slow

  # Use this if website refuses robots:
  $self->user_agent('non-robot');
  # Use this if website mucks up page format depending on browser:
  $self->{'agent_name'} = 'Mozilla/4.76';

  $self->{_next_to_retrieve} = 0;
  $self->{'_num_hits'} = 0;

  if (!defined($self->{_options}))
    {
    $self->{_options} = {
                         'search_url' => 'http://sitesearch.washingtonpost.com/cgi-bin/search99.pl',
                         'searchsection' => 'news',
                         'searchtext' => $sQuery,
                         'searchdatabase' => 'news',
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

my $WS = qr([ \t\r\n\240]);

sub preprocess_results_page_OFF
  {
  my $self = shift;
  my $sPage = shift;
  print STDERR $sPage if (2 < $self->{_debug});
  return $sPage;
  } # preprocess_results_page

sub parse_tree
  {
  my $self = shift;
  my $oTree = shift;
  my $hits_found = 0;
  if (0)
    {
    # To speed up the rest of the parsing, delete all the headers and menus:
    my @aoTABLE = $oTree->look_down('_tag', 'table');
 TABLE:
    do
      {
      my $oTABLE = shift @aoTABLE;
      my $iWidth = $oTABLE->attr('width') || 'undefined';
      if ($iWidth eq 428)
        {
        print STDERR " + found a tree whose width is $iWidth!\n" if 2 <= $self->{_debug};
        last TABLE;
        } # if
      print STDERR " + deleting a tree whose width is $iWidth...\n" if 2 <= $self->{_debug};
      $oTABLE->detach;
      $oTABLE->delete;
      } while (@aoTABLE);
    } # if 0

  # Look for the total hit count:
  my @aoFONT = $oTree->look_down(
                                 '_tag' => 'font',
                                 'color' => '#000000',
                                );
 FONT_TAG:
  foreach my $oFONT (@aoFONT)
    {
    if (ref $oFONT)
      {
      my $sFONT = $oFONT->as_text;
      print STDERR " +   try FONT == $sFONT\n" if 2 <= $self->{_debug};
      if ($sFONT =~ m!(?:\A|\s)([0-9,]+)\s+matches(?:\s|\Z)!i)
        {
        my $sCount = $1;
        # print STDERR " +     raw    count == $sCount\n" if 2 <= $self->{_debug};
        $sCount =~ s!,!!g;
        # print STDERR " +     cooked count == $sCount\n" if 2 <= $self->{_debug};
        $self->approximate_result_count($sCount);
        last FONT_TAG;
        } # if
      } # if
    } # foreach $oFONT

  # Find all the results:
  my @aoTABLE = $oTree->look_down(
                                  '_tag' => 'table',
                                  'width' => '100%',
                                 );
 TABLE_TAG:
  foreach my $oTABLE (@aoTABLE)
    {
    next TABLE_TAG unless ref $oTABLE;
    print STDERR " +   try oTABLE ===", $oTABLE->as_text, "===\n" if 2 <= $self->{_debug};
    my $oA = $oTABLE->look_down('_tag', 'a',
                                sub { ref $_[0] && ($_[0]->attr('href') =~ m!/articles/!) },
                               );
    # Make sure we have a clickable article ref:
    next TABLE_TAG unless ref $oA;
    my $sURL = $oA->attr('href');
    my $sTitle = &strip($oA->as_text);
    my $oTableSib = $oTABLE->right;
    my $sDesc = '';
    my $sDate = '';
    if (ref $oTableSib)
      {
      $sDesc = &strip($oTableSib->as_text);
      # print STDERR " +     raw sDesc ===", &octalize($sDesc), "===\n" if 2 <= $self->{_debug};
      if ($sDesc =~ m!(Page\s+\S+),$WS+(.+)\Z!i)
        {
        # This is washingtonpost format.  Extract date, keep Page # in
        # description:
        $sDesc = '['. $1 .'] ';
        $sDate = &strip($2);
        }
      elsif ($sDesc =~ m!\s*(By\s.+)$WS+(\d+:\d.+)\Z!i)
        {
        # This is AP news format, with byline.  Put byline into
        # description, rest into date:
        $sDesc = '['. &strip($1) .'] ';
        $sDate = &strip($2);
        }
      elsif ($sDesc =~ m!\s[AP]M\s!i)
        {
        # This is AP news format, without byline.  Put whole thing into date:
        $sDate = $sDesc;
        $sDesc = '';
        }
      $oTableSib = $oTableSib->right;
      if (ref $oTableSib)
        {
        $sDesc .= &strip($oTableSib->as_text);
        } # if
      } # if

    my $hit = new WWW::SearchResult;
    $hit->add_url($sURL);
    $hit->title($sTitle);
    $hit->description($sDesc);
    $hit->change_date($sDate);
    push(@{$self->{cache}}, $hit);
    $self->{'_num_hits'}++;
    $hits_found++;
    } # foreach $oTABLE

  # Find the next link, if any:
  my @aoA = $oTree->look_down('_tag', 'a');
 A_TAG:
  foreach my $oAnext (@aoA)
    {
    next A_TAG unless ref $oAnext;
    print STDERR " +   try oAnext ===", $oAnext->as_HTML, "===\n" if 2 <= $self->{_debug};
    my $oIMG = $oAnext->look_down('_tag', 'img');
    next A_TAG unless ref $oIMG;
    if ($oAnext->as_text eq 'Next')
      {
      print STDERR " +   oAnext is ===", $oAnext->as_HTML, "===\n" if 2 <= $self->{_debug};
      my $sURL = $oAnext->attr('href');
      # $sURL =~ s!&_b.\d+=&!&!g;
      # $sURL =~ s!&_NO_RETURN=1&!&!g;
      $self->{_next_url} = URI->new_abs($sURL, $self->{'_prev_url'});
      last A_TAG;
      } # if
    } # foreach $oAnext

 SKIP_NEXT_LINK:

  return $hits_found;
  } # parse_tree


sub strip
  {
  my $s = shift;
  $s =~ s!\A[\s\240]+!!x;
  $s =~ s![\s\240]+\Z!!x;
  return $s;
  } # strip


sub octalize
  {
  my $s = shift;
  return sprintf "\\%.3lo" x length($s), unpack("C*", $s);
  } # octalize


1;

__END__

URL for default GUI search results:

http://www.washingtonpost.com/cgi-bin/search99.pl?searchdatabase=serf&serf_wp=on&wp=on&description=japan+pm+bush&headline=&byline=&page=&_u.16=14

reduced URL for search results:

http://www.washingtonpost.com/cgi-bin/search99.pl?searchdatabase=serf&serf_wp=on&description=japan+pm+bush

http://search1.washingtonpost.com:80?description=Japan&searchdatabase=serf&serf_wp=on&_NO_RETURN=1&_b.11=&_NO_RETURN=1&_b.21=&_NO_RETURN=1&_b.31=&_NO_RETURN=1&_b.41=&_NO_RETURN=1&_b.51=&_NO_RETURN=1&_b.61=&_NO_RETURN=1&_b.71=/

http://search1.washingtonpost.com:80?_g.k_1=japan&_v.7=92&_u.14=1&_u.1=2&_u.2=26&_u.3=2002&_u.4=3&_u.5=11&_u.6=2002&wp=on&ap=&_b.1.x=25&_b.1.y=12/
