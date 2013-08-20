###########################################################################
#
# This file is auto-generated by the Perl DateTime Suite time locale
# generator (0.04).  This code generator comes with the
# DateTime::Locale distribution in the tools/ directory, and is called
# generate_from_cldr.
#
# This file as generated from the CLDR XML locale data.  See the
# LICENSE.cldr file included in this distribution for license details.
#
# This file was generated from the source file sr.xml.
# The source file version number was 1.88, generated on
# 2007/07/21 21:40:42.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::sr;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::root;

@DateTime::Locale::sr::ISA = qw(DateTime::Locale::root);

my @day_names = (
"понедељак",
"уторак",
"среда",
"четвртак",
"петак",
"субота",
"недеља",
);

my @day_abbreviations = (
"понедељак",
"ут\.",
"среда",
"четвртак",
"петак",
"суб\.",
"нед\.",
);

my @day_narrows = (
"п",
"у",
"с",
"ч",
"п",
"с",
"н",
);

my @month_names = (
"јануар",
"фебруар",
"март",
"април",
"мај",
"јуни",
"јули",
"аугуст",
"септембар",
"октобар",
"новембар",
"децембар",
);

my @month_abbreviations = (
"јан",
"феб",
"мар",
"апр",
"мај",
"јун",
"јул",
"авг",
"сеп",
"окт",
"нов",
"дец",
);

my @month_narrows = (
"ј",
"ф",
"м",
"а",
"м",
"ј",
"ј",
"а",
"с",
"о",
"н",
"д",
);

my @quarter_names = (
"Први\ квартал",
"Други\ квартал",
"Трећи\ квартал",
"Четврти\ квартал",
);

my @quarter_abbreviations = (
"К1",
"К2",
"К3",
"К4",
);

my @am_pms = (
"AM",
"PM",
);

my @era_names = (
"BCE",
"године",
);

my @era_abbreviations = (
"п\.н\.е\.",
"н\.е\.",
);

my $date_before_time = "1";
my $date_parts_order = "dmy";


sub day_names                      { \@day_names }
sub day_abbreviations              { \@day_abbreviations }
sub day_narrows                    { \@day_narrows }
sub month_names                    { \@month_names }
sub month_abbreviations            { \@month_abbreviations }
sub month_narrows                  { \@month_narrows }
sub quarter_names                  { \@quarter_names }
sub quarter_abbreviations          { \@quarter_abbreviations }
sub am_pms                         { \@am_pms }
sub era_names                      { \@era_names }
sub era_abbreviations              { \@era_abbreviations }
sub full_date_format               { "\%A\,\ \%d\.\ \%B\ \%\{ce_year\}\." }
sub long_date_format               { "\%d\.\ \%B\ \%\{ce_year\}\." }
sub medium_date_format             { "\%d\.\%m\.\%\{ce_year\}\." }
sub short_date_format              { "\%\{day\}\.\%\{month\}\.\%y\." }
sub full_time_format               { "\%H\ часова\,\ \%M\ минута\,\ \%S\ секунди\ vvvv" }
sub long_time_format               { "\%H\.\%M\.\%S\ \%\{time_zone_long_name\}" }
sub medium_time_format             { "\%H\.\%M\.\%S" }
sub short_time_format              { "\%H\.\%M" }
sub date_before_time               { $date_before_time }
sub date_parts_order               { $date_parts_order }



1;
