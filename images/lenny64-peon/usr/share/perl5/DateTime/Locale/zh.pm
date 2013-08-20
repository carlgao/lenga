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
# This file was generated from the source file zh.xml.
# The source file version number was 1.103, generated on
# 2007/07/24 23:39:15.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::zh;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::root;

@DateTime::Locale::zh::ISA = qw(DateTime::Locale::root);

my @day_names = (
"周一",
"周二",
"周三",
"周四",
"周五",
"周六",
"周日",
);

my @day_abbreviations = (
"周一",
"周二",
"周三",
"周四",
"周五",
"周六",
"周日",
);

my @day_narrows = (
"一",
"二",
"三",
"四",
"五",
"六",
"日",
);

my @month_names = (
"1\ 月",
"2\ 月",
"3\ 月",
"4\ 月",
"5\ 月",
"6\ 月",
"7\ 月",
"8\ 月",
"9\ 月",
"10\ 月",
"十一月",
"12\ 月",
);

my @month_abbreviations = (
"一",
"二",
"三",
"四",
"五",
"六",
"七",
"八",
"九",
"十",
"十一",
"十二",
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
"第1季度",
"第2季度",
"第3季度",
"第4季度",
);

my @quarter_abbreviations = (
"1季",
"2季",
"3季",
"4季",
);

my @am_pms = (
"上午",
"下午",
);

my @era_names = (
"公元前",
"公元",
);

my @era_abbreviations = (
"BC",
"AD",
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
sub full_date_format               { "\%\{ce_year\}年\%\{month\}月\%\{day\}日\%A" }
sub long_date_format               { "\%\{ce_year\}年\%\{month\}月\%\{day\}日" }
sub medium_date_format             { "\%\{ce_year\}\-\%\{month\}\-\%\{day\}" }
sub short_date_format              { "\%y\-\%\{month\}\-\%\{day\}" }
sub full_time_format               { "\%p\%l时\%M分\%S秒\ v" }
sub long_time_format               { "\%p\%l时\%M分\%S秒\ \%\{time_zone_long_name\}" }
sub medium_time_format             { "\%p\%l\:\%M\:\%S" }
sub short_time_format              { "\%p\%\{hour_12\}\:\%M" }
sub date_before_time               { $date_before_time }
sub date_parts_order               { $date_parts_order }



1;
