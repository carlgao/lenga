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
# This file was generated from the source file kw.xml.
# The source file version number was 1.46, generated on
# 2007/07/19 22:31:39.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::kw;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::root;

@DateTime::Locale::kw::ISA = qw(DateTime::Locale::root);

my @day_names = (
"De\ Lun",
"De\ Merth",
"De\ Merher",
"De\ Yow",
"De\ Gwener",
"De\ Sadorn",
"De\ Sul",
);

my @day_abbreviations = (
"Lun",
"Mth",
"Mhr",
"Yow",
"Gwe",
"Sad",
"Sul",
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
"Mys\ Genver",
"Mys\ Whevrel",
"Mys\ Merth",
"Mys\ Ebrel",
"Mys\ Me",
"Mys\ Efan",
"Mys\ Gortheren",
"Mye\ Est",
"Mys\ Gwyngala",
"Mys\ Hedra",
"Mys\ Du",
"Mys\ Kevardhu",
);

my @month_abbreviations = (
"Gen",
"Whe",
"Mer",
"Ebr",
"Me",
"Efn",
"Gor",
"Est",
"Gwn",
"Hed",
"Du",
"Kev",
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
"Q1",
"Q2",
"Q3",
"Q4",
);

my @quarter_abbreviations = (
"Q1",
"Q2",
"Q3",
"Q4",
);

my @am_pms = (
"a\.m\.",
"p\.m\.",
);

my @era_abbreviations = (
"RC",
"AD",
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
sub era_abbreviations              { \@era_abbreviations }
sub full_date_format               { "\%A\ \%\{day\}\ \%B\ \%\{ce_year\}" }
sub long_date_format               { "\%\{day\}\ \%B\ \%\{ce_year\}" }
sub medium_date_format             { "\%\{day\}\ \%b\ \%\{ce_year\}" }
sub short_date_format              { "\%d\/\%m\/\%\{ce_year\}" }
sub full_time_format               { "\%H\:\%M\:\%S\ v" }
sub long_time_format               { "\%H\:\%M\:\%S\ \%\{time_zone_long_name\}" }
sub medium_time_format             { "\%H\:\%M\:\%S" }
sub short_time_format              { "\%H\:\%M" }
sub date_before_time               { $date_before_time }
sub date_parts_order               { $date_parts_order }



1;

