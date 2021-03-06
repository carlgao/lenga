

=head1 NAME

WWW::Search::Null::Error - class for testing WWW::Search clients

=head1 SYNOPSIS

=begin example

  require WWW::Search;
  my $oSearch = new WWW::Search('Null::Error');
  $oSearch->native_query('Makes no difference what you search for...');
  $oSearch->retrieve_some();
  my $oResponse = $oSearch->response;
  # You get an HTTP::Response object with a code of 500

=end example

=for example_testing
is($oResponse->code, 500, 'did not get a 500 HTTP::Response');

=head1 DESCRIPTION

This class is a specialization of WWW::Search that only returns an
error message.

This module might be useful for testing a client program without
actually being connected to any particular search engine.

=head1 AUTHOR

Martin Thurn <mthurn@cpan.org>

=cut

package WWW::Search::Null::Error;

use strict;

use vars qw( @ISA );
@ISA = qw( WWW::Search );

sub native_setup_search
  {
  my($self, $native_query, $native_opt) = @_;
  } # native_setup_search


sub native_retrieve_some
  {
  my $self = shift;
  my $response = new HTTP::Response(500,
                                    "This is a test of WWW::Search");
  $self->{response} = $response;
  return undef;
  } # native_retrieve_some


1;
