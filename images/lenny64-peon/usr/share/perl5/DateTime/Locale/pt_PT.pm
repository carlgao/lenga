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
# This file was generated from the source file pt_PT.xml.
# The source file version number was 1.63, generated on
# 2007/07/23 02:08:01.
#
# Do not edit this file directly.
#
###########################################################################

package DateTime::Locale::pt_PT;

use strict;

BEGIN
{
    if ( $] >= 5.006 )
    {
        require utf8; utf8->import;
    }
}

use DateTime::Locale::pt;

@DateTime::Locale::pt_PT::ISA = qw(DateTime::Locale::pt);

my @month_names = (
"janeiro",
"fevereiro",
"março",
"abril",
"maio",
"junho",
"julho",
"agosto",
"setembro",
"outubro",
"novembro",
"dezembro",
);

my @month_abbreviations = (
"jan",
"fev",
"mar",
"abr",
"mai",
"jun",
"jul",
"ago",
"set",
"out",
"nov",
"dez",
);

my @quarter_names = (
"1º\ trimestre",
"2º\ trimestre",
"3º\ trimestre",
"4º\ trimestre",
);

my @am_pms = (
"Antes\ do\ meio\-dia",
"Depois\ do\ meio\-dia",
);

my @era_names = (
"Antes\ de\ Cristo",
"Ano\ do\ Senhor",
);

my $date_parts_order = "ymd";


sub month_names                    { \@month_names }
sub month_abbreviations            { \@month_abbreviations }
sub quarter_names                  { \@quarter_names }
sub am_pms                         { \@am_pms }
sub era_names                      { \@era_names }
sub medium_date_format             { "\%\{ce_year\}\/\%m\/\%d" }
sub short_date_format              { "\%y\/\%m\/\%d" }
sub full_time_format               { "\%HH\%Mm\%Ss\ v" }
sub date_parts_order               { $date_parts_order }



1;
