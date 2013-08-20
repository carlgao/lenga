# Lycos.pm
# by Wm. L. Scheding and Martin Thurn
# Copyright (C) 1996-1998 by USC/ISI
# $Id: Lycos.pm,v 1.32 2003/12/30 02:02:20 Daddy Exp $

=head1 NAME

WWW::Search::Lycos - class for searching www.lycos.com

=head1 SYNOPSIS

  use WWW::Search;
  my $oSearch = new WWW::Search('Lycos');
  my $sQuery = WWW::Search::escape_query("+sushi restaurant +Columbus Ohio");
  $oSearch->native_query($sQuery);
  while (my $oResult = $oSearch->next_result())
    { print $oResult->url, "\n"; }

=head1 DESCRIPTION

This class is a Lycos specialization of L<WWW::Search>.  It handles
making and interpreting Lycos-site searches F<http://www.Lycos.com>.

This class exports no public interface; all interaction should
be done through L<WWW::Search> objects.

=head1 NOTES

www.lycos.com is sometimes slow to respond; but I have not had a
problem with the default timeout.

www.lycos.com does not give the date nor size of the pages at the
resulting URLs; therefore change_date() and size() will never have a
value.

=head1 SEE ALSO

To make new back-ends, see L<WWW::Search>.

=head1 BUGS

Please tell the author if you find any!

=head1 AUTHOR

As of 1998-12-07, C<WWW::Search::Lycos> is maintained by Martin Thurn
(mthurn@cpan.org).

C<WWW::Search::Lycos> was originally written by Martin Thurn,
based on C<WWW::Search::Yahoo> version 1.12 of 1998-10-22.

=head1 LEGALESE

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.

=head1 VERSION HISTORY

For newer changes, see the file ChangeLog in the WWW-Search-Lycos distribution.

=head2 2.09, 1999-12-26

output format fixes, and query string changes for searching Lycos.com (dbradford@bdctechnologies.com)

=head2 2.08, 1999-12-22

point to new path on lycos.com (thanks to David Bradford dbradford@bdctechnologies.com)

=head2 2.07, 1999-12-10

more output format fixes, and missing 'next' link for Sites

=head2 2.05, 1999-12-03

handle new url and new output format for Lycos::Sites.pm

=head2 2.04, 1999-10-22

use strip_tags();
extract real URL from www.lycos.com's redirection URL

=head2 2.03, 1999-10-05

now uses hash_to_cgi_string()

=head2 2.02, 1999-09-30

Now able to get Web Sites results via child module Sites.pm

=head2 2.01, 1999-07-13

=head2 1.04, 1999-04-30

Now uses lycos.com's advanced query format.

=head2 1.02, 1998-12-10

First public release after being adopted by Martin Thurn.

=cut

#####################################################################

package WWW::Search::Lycos;

require Exporter;
@EXPORT = qw();
@EXPORT_OK = qw();
@ISA = qw(WWW::Search Exporter);

$VERSION = '2.21';
$MAINTAINER = 'Martin Thurn <mthurn@cpan.org>';

use Carp;
use HTML::Form;
use HTML::TreeBuilder;
use URI::Escape;
use WWW::Search qw( generic_option strip_tags unescape_query );
use WWW::SearchResult;

sub gui_query
  {
  my ($self, $sQuery, $rh) = @_;
  $self->{'_options'} = {
                         'search_url' => 'http://search.lycos.com/default.asp',
                         'query' => $sQuery,
                         'lpv' => 1,
                         'loc' => 'searchhp',
                         'tab' => 'web',
                        };
  return $self->native_query($sQuery, $rh);
  } # gui_query


sub native_setup_search
  {
  my ($self, $native_query, $native_options_ref) = @_;
  $self->{_debug} = $native_options_ref->{'search_debug'};
  $self->{_debug} = 2 if ($native_options_ref->{'search_parse_debug'});
  $self->{_debug} = 0 if (!defined($self->{_debug}));

  # lycos.com returns 10 hits per page no matter what.
  $self->{'_hits_per_page'} = 10;

  # $self->{agent_e_mail} = 'mthurn@cpan.org';
  $self->user_agent('non-robot');

  $self->{_next_to_retrieve} = 1;
  $self->{'_num_hits'} = 0;

  # The default search uses lycos.com's Advanced Search mechanism:
  if (!defined($self->{_options}))
    {
    $self->{'search_base_url'} = 'http://search.lycos.com';
    $self->{_options} = {
                         'search_url' => $self->{'search_base_url'} .'/default.asp',
						 'adv' => '1',
						 'wfc' => 3,
						 'wfq' => $native_query,
                        };
    } # if
  $self->{_options}->{'query'} = $native_query;

  my $options_ref = $self->{_options};

  # Copy in options which were passed in our second argument:
  if (defined($native_options_ref))
    {
    foreach (keys %$native_options_ref)
      {
      $options_ref->{$_} = $native_options_ref->{$_};
      } # foreach
    } # if

  # Copy in options which were set by a child object:
  if (defined($self->{'_child_options'}))
    {
    foreach (keys %{$self->{'_child_options'}})
      {
      $self->{'_options'}->{$_} = $self->{'_child_options'}->{$_};
      } # foreach
    } # if

  # Finally figure out the url.
  $self->{_next_url} = $self->{_options}{'search_url'} .'?'. $self->hash_to_cgi_string($self->{_options});
  } # native_setup_search


sub parse_tree
  {
  my $self = shift;
  my $oTree = shift;
  my $hits_found = 0;
  unless ($self_approximate_result_count)
    {
    my $oTITLE = $oTree->look_down('_tag' => 'title');
    if (ref $oTITLE)
      {
      my $sBQ = $oTITLE->as_text;
      print STDERR " +   BQ == $sBQ\n" if 2 <= $self->{_debug};
      if ($sBQ =~ m!\s*\d+\s+thru\s+\d+\s+of\s+([0-9,]+)!i)
        {
        my $sCount = $1;
        print STDERR " +     raw    count == $sCount\n" if 3 <= $self->{_debug};
        $sCount =~ s!,!!g;
        print STDERR " +     cooked count == $sCount\n" if 3 <= $self->{_debug};
        $self->approximate_result_count($sCount);
        } # if
      } # if
    } # unless
  my ($sScore, $sURL, $sTitle, $sDesc);
  my @aoIS = $oTree->look_down('_tag' => '~comment',
                               'text' => ' IS ',
                              );
 IS_TAG:
  foreach my $oIS (@aoIS)
    {
    next IS_TAG unless ref $oIS;
    print STDERR " +   oIS comment is ===". $oIS->as_HTML ."===\n" if 2 <= $self->{_debug};
    # The next element is normally a comment containing the relevance score:
    my $oREL = $oIS->right;
    if (ref($oREL)
        &&
        ($oREL->attr('_tag') eq '~comment')
       )
      {
      print STDERR " +   oREL comment is ===". $oREL->as_HTML ."===\n" if 2 <= $self->{_debug};
      if ($oREL->attr('text') =~ m!REL\s+(.+)\s*\Z!)
        {
        $sScore = $1;
        $oREL = $oREL->right;
        } # if
      } # if found REL comment
    if (ref($oREL)
        &&
        ($oREL->attr('_tag') eq 'a')
       )
      {
      $sURL = $oREL->attr('href') || '';
      unless ($sURL ne '')
        {
        next IS_TAG;
        } # unless
      $sTitle = $oREL->as_text;
      # Delete so that what's left is the description:
      $oREL->detach;
      } # if found <A>

    my $oTDhit = $oIS->parent;
    next IS_TAG unless ref $oTDhit;
    print STDERR " +   oTDhit is ===". $oTDhit->as_HTML ."===\n" if 2 <= $self->{_debug};
    my $oSPAN = $oTDhit->look_down(_tag => 'span');
    if (ref $oSPAN)
      {
      $oSPAN->detach;
      $oSPAN->delete;
      } # if
    my $sDesc = $oTDhit->as_text;
    print STDERR " +   found desc ===$sDesc===\n" if 2 <= $self->{_debug};

    my $hit = new WWW::SearchResult;
    $hit->add_url($sURL);
    $hit->title($sTitle);
    $hit->description(&WWW::Search::strip_tags($sDesc));
    $hit->score($sScore);
    push(@{$self->{cache}}, $hit);
    $self->{'_num_hits'}++;
    $hits_found++;
    } # foreach $oB
  # Find the next link, if any:
  my @aoA = $oTree->look_down('_tag', 'a',
                             sub { $_[0]->as_text eq 'Next' } );
 A_TAG:
  # We want the last "next" link on the page:
  my $oA = $aoA[-1];
  if (ref $oA)
    {
    print STDERR " +   oAnext is ===", $oA->as_HTML, "===\n" if 2 <= $self->{_debug};
    $self->{_next_url} = $self->absurl($self->{'_prev_url'}, $oA->attr('href'));
    } # if
 SKIP_NEXT_LINK:

  return $hits_found;
  } # parse_tree


1;

__END__

2002-07 adanced query:
http://search.lycos.com/default.asp?loc=searchbox&tab=&query=&adv=1&wfr=&wfw=&wfq=Martin+Thurn&wfr=%2B&wfw=&wfq=&wfr=-&wfw=&wfq=&wfc=3&df0=i&dfq=&df1=e&dfq=&dfc=2&lang=&ca=&submit_button=Submit+Search
http://search.lycos.com/default.asp?adv=1&wfq=Martin+Thurn&wfc=3&df0=i&dfc=2
http://search.lycos.com/default.asp?adv=1&wfq=Martin+Thurn&wfc=3

2002-07 gui query:
http://search.lycos.com/default.asp?lpv=1&loc=searchhp&query=Martin+Thurn
