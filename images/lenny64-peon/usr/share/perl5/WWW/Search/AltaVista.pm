# AltaVista.pm
# by John Heidemann
# Copyright (C) 1996-1998 by USC/ISI
# $Id: AltaVista.pm,v 2.30 2003-11-24 21:08:27-05 kingpin Exp kingpin $
#
# Complete copyright notice follows below.

=head1 NAME

WWW::Search::AltaVista - class for searching www.altavista.com


=head1 SYNOPSIS

    require WWW::Search;
    $search = new WWW::Search('AltaVista');


=head1 DESCRIPTION

This class is an AltaVista specialization of WWW::Search.
It handles making and interpreting AltaVista searches
F<http://www.altavista.com>.

This class exports no public interface; all interaction should
be done through WWW::Search objects.


=head1 OPTIONS

The default is "any of these words" (OR of query terms).

=over 8

=item aqa=all+of+these+words

Add the AND of these words to the query.

=item aqp=this+exact+phrase

Add "this exact phrase" to the query.

=item aqo=any+of+these+words

Add the OR of these words to the query.
This is where the query is placed by default.

=item aqn=none+of+these+words

Add NOT these words to the query.

=item aqb=(boolean+AND+expression)+NEAR+entry

Add a boolean expression to the query.
Operators are AND, OR, AND NOT, and NEAR.
In the browser interface, the boolean expression can not be combined with any other query types listed above.
You should probably build the boolean expression with parentheses and spaces and urlescape it.

=item aqs=these+words

Pages containing "these words" will be ranked highest.

=item kgs=[0,1]

To restrict the search to U.S. websites, set kgs=1.
The default is world-wide, kgs=0.

=item kls=[0,1]

To restrict the search to pages in English and Spanish, set kls=1.
The default is no language restrictions, kls=0.

=item filetype=[html,pdf]

To restrict the search to HTML pages only, set filetype=html.
To restrict the search to PDF pages only, set filetype=pdf.
The default is no restriction on page type, filetype=.

=item rc=dmn&swd=net+org+or.jp

To restrict the search to pages from certain domains,
set rc=dmn and set swd to a list of desired toplevel domains.

=item rc=url&lh=www.sandcrawler.com/SWB

To restrict the search to pages from a particular site,
set rc=url and set lh to the site name and path.
Leave off the http:// from the site.

=back

=head1 BUGS

=over

=item Not all of the above options have been tested.

=back

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>,
or the specialized AltaVista searches described in options.


=head1 AUTHOR

C<WWW::Search::AltaVista> was written by John Heidemann,
<johnh@isi.edu>.
C<WWW::Search::AltaVista> is maintained by Martin Thurn,
<mthurn@cpan.org>.

=head1 COPYRIGHT

Copyright (c) 1996-1998 University of Southern California.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation, advertising
materials, and other materials related to such distribution and use
acknowledge that the software was developed by the University of
Southern California, Information Sciences Institute.  The name of the
University may not be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=cut

#####################################################################

package WWW::Search::AltaVista;

use Carp ();
use Exporter;
use WWW::Search qw( generic_option strip_tags unescape_query );
use WWW::Search::Result;

use strict;

use vars qw( @ISA @EXPORT @EXPORT_OK $VERSION $MAINTAINER );

@EXPORT = qw();
@EXPORT_OK = qw();
@ISA = qw(WWW::Search Exporter);
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';
$VERSION = sprintf("%d.%02d", q$Revision: 2.30 $ =~ /(\d+)\.(\d+)/o);


sub undef_to_emptystring
  {
  return defined($_[0]) ? $_[0] : "";
  }


sub gui_query
  {
  my ($self, $sQuery, $rh) = @_;
  $self->{'_options'} = {
                         'search_host' => 'http://www.altavista.com',
                         'search_path' => '/web/results',
                         'q' => $sQuery,
                         'kls' => 0,
                         avkw => 'qtrp',
                        };
  return $self->native_query($sQuery, $rh);
  } # gui_query


# private
sub native_setup_search
  {
  my ($self, $native_query, $native_options_ref) = @_;
  $self->user_agent('user');
  $self->{_next_to_retrieve} = 0;
  if (!defined($self->{_options}))
    {
    $self->{_options} = {
                         'pg' => 'aq',
                         'avkw' => 'qtrp',
                         'aqmode' => 's',
                         'aqo' => $native_query,
                         'kgs' => 0,
                         'kls' => 0,
                         # 'dt' => 'dtrange',
                         'rc' => 'dmn',
                         'nbq' => '50',
                         'search_host' => 'http://www.altavista.com',
                         'search_path' => '/web/results',
                        };
    if ((my $s = $self->date_from) ne '')
      {
      $s = &UnixDate($s, '%m/%d/%y');
      $self->{_options}->{d0} = $s;
      $self->{_options}->{dt} = 'dtrange';
      } # if
    if ((my $s = $self->date_to) ne '')
      {
      $s = &UnixDate($s, '%m/%d/%y');
      $self->{_options}->{d1} = $s;
      $self->{_options}->{dt} = 'dtrange';
      } # if
    } # if
  my($options_ref) = $self->{_options};
  if (defined($native_options_ref))
    {
    # Copy in new options.
    foreach (keys %$native_options_ref)
      {
      $options_ref->{$_} = $native_options_ref->{$_};
      } # foreach
    } # if
  # Process the options.
  my $options = '';
  # For Intranet search to work, mss option must be first:
  if (exists $options_ref->{'mss'})
    {
    $options .= 'mss=' . $options_ref->{'mss'} . '&';
    } # if
  foreach my $key (keys %$options_ref)
    {
    # printf STDERR "option: $_ is " . $options_ref->{$_} . "\n";
    next if (generic_option($key));
    next if $key eq 'mss';
    $options .= $key . '=' . $options_ref->{$key} . '&';
    } # foreach
  chop $options;
  $self->{_debug} = $options_ref->{'search_debug'};
  $self->{_debug} = 2 if ($options_ref->{'search_parse_debug'});
  $self->{_debug} = 0 if (!defined($self->{_debug}));
  # Pattern for matching result-count in many languages:
  $self->{'_qr_count'} = qr{\s(?:found|fand).+?([\d.,]+)\s+(result|headline|Ergebnisse)};

  # Finally figure out the url.
  $self->{_base_url} =
  $self->{_next_url} =
  $self->{_options}{'search_host'} . $self->{_options}{'search_path'} .'?'. $options;
  # print STDERR $self->{_base_url} . "\n" if ($self->{_debug});
  } # native_setup_search


sub preprocess_results_page_DEBUG
  {
  my $self = shift;
  my $sPage = shift;
  # return $sPage;
  # For debugging only.  Print the page contents and abort.
  print STDERR $sPage;
  exit 88;
  } # preprocess_results_page


# private
sub save_old_hit {
    my($self) = shift;
    my($old_hit) = shift;
    my($old_raw) = shift;

    if (defined($old_hit)) {
    $old_hit->raw($old_raw) if (defined($old_raw));
    push(@{$self->{cache}}, $old_hit);
    };

    return(undef, undef);
}

# private
sub begin_new_hit
{
    my($self) = shift;
    my($old_hit) = shift;
    my($old_raw) = shift;

    $self->save_old_hit($old_hit, $old_raw);

    # Make a new hit.
    return (new WWW::SearchResult, '');
}


sub parse_tree
  {
  my $self = shift;
  my $tree = shift;
  my $iHits = 0;
  my $iCountSpoof = 0;
  my $WS = q{[\t\r\n\240\ ]};
  # Get rid of "sponsored" results:
  my @aoTABLE = $tree->look_down('_tag' => 'table',
                                 'width' => '70%',
                                 );
 TREE_TAG:
  foreach (1..2)
    {
    my $oTREE = shift @aoTABLE;
    last unless ref $oTREE;
    $oTREE->detach;
    $oTREE->delete;
    } # for
  # Only try to parse the hit count if we haven't done so already:
  print STDERR " + start, approx_h_c is ==", $self->approximate_hit_count(), "==\n" if 2 <= $self->{_debug};
  if ($self->approximate_hit_count() < 1)
    {
    # Sometimes the hit count is inside a <DIV> tag:
    my @aoDIV = $tree->look_down('_tag' => 'div',
                                  'class' => 'xs',
                                 );
 DIV_TAG:
    foreach my $oDIV (@aoDIV)
      {
      next unless ref $oDIV;
      print STDERR " + try DIV ==", $oDIV->as_HTML if 2 <= $self->{_debug};
      my $s = $oDIV->as_text;
      print STDERR " +   TEXT ==$s==\n" if 2 <= $self->{_debug};
      if ($s =~ m!$self->{_qr_count}!i)
        {
        my $iCount = $1;
        $iCount =~ tr!.,!!d;
        $self->approximate_result_count($iCount);
        last DIV_TAG;
        } # if
      } # foreach DIV_TAG
    } # if
  print STDERR " + found approx_h_c is ==", $self->approximate_hit_count(), "==\n" if 2 <= $self->{_debug};
  # Get the hits:
  my @aoA = $tree->look_down('_tag' => 'a',
                             'class' => 'res',
                            );
 A_TAG:
  foreach my $oA (@aoA)
    {
    next unless ref $oA;
    my $sTitle = $oA->as_text;
    my $oSPAN = $oA;
    do
      {
      $oSPAN = $oSPAN->right;
      last if ! ref $oSPAN;
      } until ($oSPAN->tag eq 'span');
    if (ref $oSPAN)
      {
      my $oSPANurl = $oSPAN->look_down(
                                       '_tag' => 'span',
                                       'class' => 'ngrn',
                                      );
      if (ref $oSPANurl)
        {
        my $oHit = new WWW::Search::Result;
        $oHit->add_url($self->absurl($self->{'_prev_url'},
                                     $oSPANurl->as_text));
        $oSPANurl->detach;
        $oSPANurl->delete;
        $oHit->title($sTitle);
        $oHit->description(&WWW::Search::strip_tags($oSPAN->as_text));
        push(@{$self->{cache}}, $oHit);
        $self->{'_num_hits'}++;
        $iHits++;
        } # if
      } # if
    $oA->detach;
    $oA->delete;
    } # foreach A_TAG
  # Find the 'next page' link:
  @aoA = $tree->look_down('_tag' => 'a',
                         );
 NEXT_TAG:
  foreach my $oA (@aoA)
    {
    next NEXT_TAG unless ref $oA;
    # Multilingual version:
    next NEXT_TAG unless $oA->as_text =~ m!\s>>\Z!;
    # English-only version:
    # next NEXT_TAG unless $oA->as_text eq q{Next >>};
    $self->{_next_url} = $self->absurl($self->{'_prev_url'}, $oA->attr('href'));
    last NEXT_TAG;
    } # foreach
  return $iHits;
  } # parse_tree

# private
sub native_retrieve_some_OLD
{
    my ($self) = @_;

    # fast exit if already done
    return undef if (!defined($self->{_next_url}));

    # get some
    print STDERR "WWW::Search::AltaVista::native_retrieve_some: fetching " . $self->{_next_url} . "\n" if ($self->{_debug});
    my($response) = $self->http_request('GET', $self->{_next_url});
    $self->{response} = $response;
    if (! $response->is_success)
      {
      print STDERR " +   failed: ", $response->as_string if ($self->{_debug});
      return undef;
      } # if

    print STDERR $response->content;
    exit 88;

    # parse the output
    my ($HEADER, $HITS, $INHIT, $TRAILER, $POST_NEXT) = (1..10);  # order matters
    my $hits_found = 0;
    my $state = $HEADER;
    my $hit = undef;
    my $raw = '';
    foreach ($self->split_lines($response->content()))
      {
      next if m/^$/; # short circuit for blank lines
      print STDERR "PARSE(0:RAW): $_\n" if ($self->{_debug} >= 3);

      ######
      # HEADER PARSING: find the number of hits
      #
      if ($state == $HEADER && /(?:AltaVista|We)\s+(?:found|fand).*?([\d,]+)\s+(results?|headlines?|Ergebnisse)/i)
        {
        # Modified by Jim
        my $n = $1;
        $n =~ s/[.,]//g;
        $self->approximate_result_count($n);
        print STDERR "PARSE(10:HEADER->HITS): $n documents found.\n" if ($self->{_debug} >= 2);
        return 0 unless (0 < $n);
        $state = $HITS;
        }

        ######
        # HITS PARSING: find each hit
        #
      elsif ($state == $HITS && /r=(.*?)"\s.*?">(.*)<\/a>/i)
        {
        $raw .= $_;
        my ($url, $title) = (unescape_query($1), $2);
        print STDERR "PARSE(13:INHIT): url+title: $title.\n" if ($self->{_debug} >= 2);
        if ($title !~ m!\A<img!i)
          {
          ($hit, $raw) = $self->begin_new_hit($hit, $raw);
          $hits_found++;
          $hit->add_url($url);
          $hit->title($title);
          } # if
        }
      elsif ($state == $HITS && /^URL:\s(.*)$/i)
        {
        $raw .= $_;
        print STDERR "PARSE(13:INHIT): url: $1.\n" if ($self->{_debug} >= 2);
        }

      if (0 && $state == $HITS && /^<br>/i)
        {
        }

      if (($state == $HITS) &&
          (m/^([\d|\w|<b>|\.].+?)<br>/i ||
           m!<span\s+class=s>(.+?)<br>!i))
        {
        # We are looking at a description...
        if (ref $hit)
          {
          # AND we have already seen a URL.
          $raw .= $_;
          $hit->description(&strip_tags($1));
          } # if
        print STDERR "PARSE(13:INHIT): description.\n" if ($self->{_debug} >= 2);
        }
      # Look for end of hits list:
      if (($state == $HITS)
          &&
          (
           /^<!-- res_extend.wm -->/i
           ||
           m!<a\s+href="/r\?ext24"!i
           ||
           m!<a\s+href="http://jump.altavista.com/rlweb_ebay.go!i
          )
         )
        {
        ($hit, $raw) = $self->save_old_hit($hit, $raw);
        $state = $TRAILER;
        print STDERR "PARSE(13:INHIT->HITS): end hit.\n" if ($self->{_debug} >= 2);
        }
      if ($hits_found &&
          (($state == $TRAILER)
           ||
           ($state == $HITS))
          &&
          m/<a[^>]+href="([^"]+)"[^>]*>[^>]+&gt;&gt;/i)
        {
        # (above, note the trick $hits_found so we don't prematurely terminate.)
        # set up next page
        my $relative_url = $1;
        # Actual line of input:
        # &nbsp; <a href="/cgi-bin/query?pg=q&amp;nbq=50&amp;what=web&amp;text=yes&amp;fmt=d&amp;q=Martin+Thurn&stq=50" target="_self">[Next &gt;&gt;]</a>

        print STDERR "PARSE(15:->POST_NEXT): raw next_url is $relative_url\n" if ($self->{_debug} >= 2);
        # hack:  make sure fmt=d stays on news URLs
        $relative_url =~ s/what=news/what=news\&fmt=d/ if ($relative_url !~ /fmt=d/i);
        # Not sure why this is necessary.  BUT I *have* seen
        # altavista.com spit out double-encoded URLs!  I.e. they
        # contain &amp;amp; !!
        $relative_url =~ s!&amp;!&!g;
        my $sURLtry = $self->absurl($self->{_base_url}, $relative_url);
        printf(STDERR "PARSE(15:->POST_NEXT): cooked next_url is $sURLtry.\n") if ($self->{_debug} >= 2);
        if ($sURLtry =~ m!$self->{_options}->{search_host}$self->{_options}->{search_path}!)
          {
          # This really is the next URL.
          $self->{_next_url} = $sURLtry;
          $state = $POST_NEXT;
          } # if
        } # if

      if (0 && ($state == $HITS))
        {
        # other random stuff in a hit---accumulate it
        $raw .= $_;
        print STDERR "PARSE(14:INHIT): no match.\n" if ($self->{_debug} >= 2);
        print STDERR ' 'x 12, "$_\n" if ($self->{_debug} >= 3);
        }
      else
        {
        # accumulate raw
        $raw .= $_;
        # print STDERR "PARSE(RAW): $_\n" if ($self->{_debug} >= 3);
        }
      }

    if ($state != $POST_NEXT)
      {
      # end, no other pages (missed ``next'' tag)
      if ($state == $HITS)
        {
        $self->begin_new_hit($hit, $raw);   # save old one
        print STDERR "PARSE: never got to TRAILER.\n" if ($self->{_debug} >= 2);
        }
      $self->{_next_url} = undef;
      }

    # sleep so as to not overload altavista
    $self->user_agent_delay if (defined($self->{_next_url}));

    return $hits_found;
    } # native_retrieve_some

1;

__END__

advanced search results:
http://www.altavista.com/web/results?pg=aq&avkw=qtrp&aqmode=s&aqa=&aqp=&aqo=martin+thurn&aqn=&aqb=&aqs=&kgs=0&kls=0&dt=tmperiod&d2=0&d0=&d1=&filetype=&rc=dmn&swd=&lh=&nbq=50

gui query results:
http://www.altavista.com/web/results?q=Rhonda+Thurn&kgs=0&kls=0&avkw=qtrp
