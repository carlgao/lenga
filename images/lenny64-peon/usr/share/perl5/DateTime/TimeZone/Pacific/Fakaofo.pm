# This file is auto-generated by the Perl DateTime Suite time zone
# code generator (0.07) This code generator comes with the
# DateTime::TimeZone module distribution in the tools/ directory

#
# Generated from debian/tzdata/australasia.  Olson data version 2008c
#
# Do not edit this file directly.
#
package DateTime::TimeZone::Pacific::Fakaofo;

use strict;

use Class::Singleton;
use DateTime::TimeZone;
use DateTime::TimeZone::OlsonDB;

@DateTime::TimeZone::Pacific::Fakaofo::ISA = ( 'Class::Singleton', 'DateTime::TimeZone' );

my $spans =
[
    [
DateTime::TimeZone::NEG_INFINITY,
59958271496,
DateTime::TimeZone::NEG_INFINITY,
59958230400,
-41096,
0,
'LMT'
    ],
    [
59958271496,
DateTime::TimeZone::INFINITY,
59958235496,
DateTime::TimeZone::INFINITY,
-36000,
0,
'TKT'
    ],
];

sub olson_version { '2008c' }

sub has_dst_changes { 0 }

sub _max_year { 2018 }

sub _new_instance
{
    return shift->_init( @_, spans => $spans );
}



1;

