# This file is auto-generated by the Perl DateTime Suite time zone
# code generator (0.07) This code generator comes with the
# DateTime::TimeZone module distribution in the tools/ directory

#
# Generated from debian/tzdata/australasia.  Olson data version 2008c
#
# Do not edit this file directly.
#
package DateTime::TimeZone::Pacific::Pitcairn;

use strict;

use Class::Singleton;
use DateTime::TimeZone;
use DateTime::TimeZone::OlsonDB;

@DateTime::TimeZone::Pacific::Pitcairn::ISA = ( 'Class::Singleton', 'DateTime::TimeZone' );

my $spans =
[
    [
DateTime::TimeZone::NEG_INFINITY,
59958261620,
DateTime::TimeZone::NEG_INFINITY,
59958230400,
-31220,
0,
'LMT'
    ],
    [
59958261620,
63029349000,
59958231020,
63029318400,
-30600,
0,
'PNT'
    ],
    [
63029349000,
DateTime::TimeZone::INFINITY,
63029320200,
DateTime::TimeZone::INFINITY,
-28800,
0,
'PST'
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
