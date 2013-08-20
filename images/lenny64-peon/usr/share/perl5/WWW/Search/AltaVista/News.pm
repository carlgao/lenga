# News.pm
# by John Heidemann
# Copyright (C) 1996 by USC/ISI
# $Id: News.pm,v 1.6 2003-11-24 21:07:58-05 kingpin Exp kingpin $
#
# Complete copyright notice follows below.

=head1 NAME

WWW::Search::AltaVista::News - class for Alta Vista news searching


=head1 SYNOPSIS

    require WWW::Search;
    $search = new WWW::Search('AltaVista::News');


=head1 DESCRIPTION

This class implements the AltaVista news search
(specializing AltaVista and WWW::Search).
It handles making and interpreting AltaVista news searches
F<http://www.altavista.com>.

Details of AltaVista can be found at L<WWW::Search::AltaVista>.

This class exports no public interface; all interaction should
be done through WWW::Search objects.


=head1 AUTHOR

C<WWW::Search> is written by John Heidemann, <johnh@isi.edu>.


=head1 COPYRIGHT

Copyright (c) 1996 University of Southern California.
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

package WWW::Search::AltaVista::News;

use Date::Manip;
use Exporter;
use WWW::Search::AltaVista;

use strict;
use vars qw( @EXPORT @EXPORT_OK @ISA $MAINTAINER $VERSION );

@EXPORT = qw();
@EXPORT_OK = qw();
@ISA = qw(WWW::Search::AltaVista Exporter);
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';
$VERSION = sprintf("%d.%02d", q$Revision: 1.6 $ =~ /(\d+)\.(\d+)/o);

# private
sub native_setup_search
  {
  my $self = shift;
  my $sQuery = shift;
  if (!defined($self->{_options})) {
    $self->{_options} = {
                         'nbq' => '50',
                         'q' => $sQuery,
                         'search_host' => 'http://news.altavista.com',
                         'search_path' => '/news/search',
                        };
    };
  # If I use 'US/Eastern', Date::Manip gives undef warnings:
  &Date_Init('TZ=-0500');
  # Let AltaVista.pm finish up the hard work:
  return $self->SUPER::native_setup_search($sQuery, @_);
  } # native_setup_search

sub parse_tree
  {
  my $self = shift;
  my $tree = shift;
  my $iHits = 0;
  my $WS = q{[\t\r\n\240\ ]};
  # Only try to parse the hit count if we haven't done so already:
  print STDERR " + start, approx_h_c is ==", $self->approximate_hit_count(), "==\n" if 2 <= $self->{_debug};
  if ($self->approximate_hit_count() < 1)
    {
    # The hit count is inside a <B> tag:
    my @aoB = $tree->look_down('_tag' => 'b',
                               'class' => 'lbl',
                              );
 B_TAG:
    foreach my $oB (@aoB)
      {
      next unless ref $oB;
      print STDERR " + try B ==", $oB->as_HTML if 2 <= $self->{_debug};
      my $s = $oB->as_text;
      print STDERR " +   TEXT ==$s==\n" if 2 <= $self->{_debug};
      if ($s =~ m!$self->{_qr_count}!i)
        {
        my $iCount = $1;
        $iCount =~ s!,!!g;
        $self->approximate_result_count($iCount);
        last B_TAG;
        } # if
      } # foreach B_TAG
    } # if
  print STDERR " + found approx_h_c is ==", $self->approximate_hit_count(), "==\n" if 2 <= $self->{_debug};
  # Get the hits:
  my @aoA = $tree->look_down('_tag' => 'a',
                            );
 A_TAG:
  foreach my $oA (@aoA)
    {
    next unless ref $oA;
    my $sMouseover = $oA->attr('onMouseOver') || '';
    next A_TAG if ($sMouseover eq '');
    next A_TAG unless ($sMouseover =~ m!status='(.+?)';!);
    my $sURL = $1;
    my $sTitle = $oA->as_text;
    print STDERR " + oA ==", $oA->as_HTML, "==\n" if (2 <= $self->{_debug});
    print STDERR " + sTitle ==$sTitle==\n" if (2 <= $self->{_debug});
    my $oSPAN = $oA;
    $oA->parent->objectify_text;
    my $sDescription = '';
    # print STDERR " +   start grabbing description...\n" if (2 <= $self->{_debug});
 SPAN:
    while (1)
      {
      $oSPAN = $oSPAN->right;
      last SPAN if ! defined($oSPAN);
      # print STDERR " +     consider SPAN ==$oSPAN==\n" if (2 <= $self->{_debug});
      # $oSPAN->dump(\*STDERR);
      last SPAN if (ref($oSPAN) && ($oSPAN->tag eq 'span'));
      if ($oSPAN->tag eq '~text')
        {
        $sDescription .= $oSPAN->attr('text');
        }
      else
        {
        $sDescription .= $oSPAN->as_text;
        }
      # print STDERR " +     desc is now ==$sDescription==\n" if (2 <= $self->{_debug});
      } # while
    $oA->parent->deobjectify_text;
    next A_TAG unless (ref $oSPAN);
    my $oSPANdate = $oSPAN->look_down(
                                      '_tag' => 'span',
                                      'class' => 'ngrn',
                                     );
    next A_TAG unless (ref $oSPANdate);
    print STDERR " + oSPANdate ==", $oSPANdate->as_HTML, "==\n" if (2 <= $self->{_debug});
    my $sDate = $oSPANdate->as_text;
    print STDERR " +   raw     sDate ==$sDate==\n" if (2 <= $self->{_debug});
    $sDate =~ s!\A\s*(?:Found|Fand)\s+!!i;
    print STDERR " +   poached sDate ==$sDate==\n" if (2 <= $self->{_debug});
    my $sErr;
    my $sDate1 = &DateCalc('now', $sDate, \$sErr);
    print STDERR " +   DateCalc result ==$sDate1==$sErr==\n" if (2 <= $self->{_debug});
    my $sDate2 = &UnixDate($sDate1, '%Y-%m-%d %H:%M');
    print STDERR " +   cooked  sDate ==$sDate2==\n" if (2 <= $self->{_debug});
    $oSPANdate->detach;
    $oSPANdate->delete;

    my $oHit = new WWW::Search::Result;
    $oHit->add_url($self->absurl($self->{'_prev_url'}, $sURL));
    $oHit->title(&WWW::Search::strip_tags($sTitle));
    print STDERR " + oSPAN ==", $oSPAN->as_HTML, "==\n" if (2 <= $self->{_debug});
    $oHit->source(&WWW::Search::strip_tags($oSPAN->as_text));
    $oHit->description(&WWW::Search::strip_tags($sDescription));
    $oHit->change_date($sDate2);
    push(@{$self->{cache}}, $oHit);
    $self->{'_num_hits'}++;
    $iHits++;
    # Make it easier to find the "Next" tag:
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

1;
