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
# This file was generated from the source file ln.xml.
# The source file version number was 1.31, generated on
# 2007/07/19 23:30:28.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::ln;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::root;

@DateTime::Locale::ln::ISA = qw(DateTime::Locale::root);

my @day_names = (
"mokɔlɔ\ ya\ libosó",
"mokɔlɔ\ ya\ míbalé",
"mokɔlɔ\ ya\ mísáto",
"mokɔlɔ\ ya\ mínéi",
"mokɔlɔ\ ya\ mítáno",
"mpɔ́sɔ",
"eyenga",
);

my @day_abbreviations = (
"m1",
"m2",
"m3",
"m4",
"m5",
"mps",
"eye",
);

my @day_narrows = (
"2",
"3",
"4",
"5",
"6",
"7",
"1",
);

my @month_names = (
"sánzá\ ya\ yambo",
"sánzá\ ya\ míbalé",
"sánzá\ ya\ mísáto",
"sánzá\ ya\ mínéi",
"sánzá\ ya\ mítáno",
"sánzá\ ya\ motóbá",
"sánzá\ ya\ nsambo",
"sánzá\ ya\ mwambe",
"sánzá\ ya\ libwa",
"sánzá\ ya\ zómí",
"sánzá\ ya\ zómí\ na\ mɔ̌kɔ́",
"sánzá\ ya\ zómí\ na\ míbalé",
);

my @month_abbreviations = (
"s1",
"s2",
"s3",
"s4",
"s5",
"s6",
"s7",
"s8",
"s9",
"s10",
"s11",
"s12",
);

my @month_narrows = (
"1",
"2",
"3",
"4",
"5",
"6",
"7",
"8",
"9",
"10",
"11",
"12",
);

my @quarter_names = (
"sánzá\ mísáto\ ya\ yambo",
"sánzá\ mísáto\ ya\ míbalé",
"sánzá\ mísáto\ ya\ mísáto",
"sánzá\ mísáto\ ya\ mínéi",
);

my @quarter_abbreviations = (
"SM1",
"SM2",
"SM3",
"SM4",
);

my @am_pms = (
"AM",
"PM",
);

my @era_names = (
"libosó\ ya\ Y\.\-K\.",
"nsima\ ya\ Y\.\-K\.",
);

my @era_abbreviations = (
"libosó\ ya\ Y\.\-K\.",
"nsima\ ya\ Y\.\-K\.",
);

my $date_before_time = "1";
my $date_parts_order = "ymd";


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
sub full_date_format               { "\%A\,\ \%\{ce_year\}\ \%B\ \%d" }
sub long_date_format               { "\%\{ce_year\}\ \%B\ \%\{day\}" }
sub medium_date_format             { "\%\{ce_year\}\ \%b\ \%\{day\}" }
sub short_date_format              { "\%y\/\%m\/\%d" }
sub full_time_format               { "\%H\:\%M\:\%S\ v" }
sub long_time_format               { "\%H\:\%M\:\%S\ \%\{time_zone_long_name\}" }
sub medium_time_format             { "\%H\:\%M\:\%S" }
sub short_time_format              { "\%H\:\%M" }
sub date_before_time               { $date_before_time }
sub date_parts_order               { $date_parts_order }



1;
