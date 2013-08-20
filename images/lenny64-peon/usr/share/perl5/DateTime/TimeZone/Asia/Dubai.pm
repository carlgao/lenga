# This file is auto-generated by the Perl DateTime Suite time zone
# code generator (0.07) This code generator comes with the
# DateTime::TimeZone module distribution in the tools/ directory

#
# Generated from debian/tzdata/asia.  Olson data version 2008c
#
# Do not edit this file directly.
#
package DateTime::TimeZone::Asia::Dubai;

use strict;

use Class::Singleton;
use DateTime::TimeZone;
use DateTime::TimeZone::OlsonDB;

@DateTime::TimeZone::Asia::Dubai::ISA = ( 'Class::Singleton', 'DateTime::TimeZone' );

my $spans =
[
    [
DateTime::TimeZone::NEG_INFINITY,
60557746728,
DateTime::TimeZone::NEG_INFINITY,
60557760000,
13272,
0,
'LMT'
    ],
    [
60557746728,
DateTime::TimeZone::INFINITY,
60557761128,
DateTime::TimeZone::INFINITY,
14400,
0,
'GST'
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

