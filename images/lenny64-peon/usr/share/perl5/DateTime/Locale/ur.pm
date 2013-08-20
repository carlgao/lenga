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
# This file was generated from the source file ur.xml.
# The source file version number was 1.46, generated on
# 2007/07/21 17:40:15.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::ur;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::root;

@DateTime::Locale::ur::ISA = qw(DateTime::Locale::root);

my @day_names = (
"پیر",
"منگل",
"بده",
"جمعرات",
"جمعہ",
"ہفتہ",
"اتوار",
);

my @day_narrows = (
"پیر",
"منگ",
"بدھ",
"جمعرات",
"جمعہ",
"ہفتہ",
"اتوار",
);

my @month_names = (
"جنوری",
"فروری",
"مارچ",
"اپریل",
"مئ",
"جون",
"جولائ",
"اگست",
"ستمبر",
"اکتوبر",
"نومبر",
"دسمبر",
);

my @quarter_names = (
"پہلی\ سہ\ ماہی",
"دوسری\ سہ\ ماہی",
"تيسری\ سہ\ ماہی",
"چوتهی\ سہ\ ماہی",
);

my @am_pms = (
"AM",
"PM",
);

my @era_names = (
"قبل\ مسيح",
"عيسوی\ سن",
);

my @era_abbreviations = (
"ق\ م",
"عيسوی\ سن",
);

my $date_before_time = "1";
my $date_parts_order = "ymd";


sub day_names                      { \@day_names }
sub day_narrows                    { \@day_narrows }
sub month_names                    { \@month_names }
sub quarter_names                  { \@quarter_names }
sub am_pms                         { \@am_pms }
sub era_names                      { \@era_names }
sub era_abbreviations              { \@era_abbreviations }
sub full_date_format               { "\%A\,\ \%\{ce_year\}\ \%B\ \%d" }
sub long_date_format               { "\%\{ce_year\}\ \%B\ \%\{day\}" }
sub medium_date_format             { "\%\{ce_year\}\ \%b\ \%\{day\}" }
sub short_date_format              { "\%\{ce_year\}\-\%m\-\%d" }
sub full_time_format               { "\%H\:\%M\:\%S\ v" }
sub long_time_format               { "\%H\:\%M\:\%S\ \%\{time_zone_long_name\}" }
sub medium_time_format             { "\%H\:\%M\:\%S" }
sub short_time_format              { "\%H\:\%M" }
sub date_before_time               { $date_before_time }
sub date_parts_order               { $date_parts_order }



1;

