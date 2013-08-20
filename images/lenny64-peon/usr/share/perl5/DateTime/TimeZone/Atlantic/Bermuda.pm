# This file is auto-generated by the Perl DateTime Suite time zone
# code generator (0.07) This code generator comes with the
# DateTime::TimeZone module distribution in the tools/ directory

#
# Generated from debian/tzdata/northamerica.  Olson data version 2008c
#
# Do not edit this file directly.
#
package DateTime::TimeZone::Atlantic::Bermuda;

use strict;

use Class::Singleton;
use DateTime::TimeZone;
use DateTime::TimeZone::OlsonDB;

@DateTime::TimeZone::Atlantic::Bermuda::ISA = ( 'Class::Singleton', 'DateTime::TimeZone' );

my $spans =
[
    [
DateTime::TimeZone::NEG_INFINITY,
60873401944,
DateTime::TimeZone::NEG_INFINITY,
60873386400,
-15544,
0,
'LMT'
    ],
    [
60873401944,
62272044000,
60873387544,
62272029600,
-14400,
0,
'AST'
    ],
    [
62272044000,
62287765200,
62272033200,
62287754400,
-10800,
1,
'ADT'
    ],
    [
62287765200,
62303493600,
62287750800,
62303479200,
-14400,
0,
'AST'
    ],
    [
62303493600,
62319214800,
62303482800,
62319204000,
-10800,
1,
'ADT'
    ],
    [
62319214800,
62325000000,
62319200400,
62324985600,
-14400,
0,
'AST'
    ],
    [
62325000000,
62334943200,
62324985600,
62334928800,
-14400,
0,
'AST'
    ],
    [
62334943200,
62351269200,
62334932400,
62351258400,
-10800,
1,
'ADT'
    ],
    [
62351269200,
62366392800,
62351254800,
62366378400,
-14400,
0,
'AST'
    ],
    [
62366392800,
62382718800,
62366382000,
62382708000,
-10800,
1,
'ADT'
    ],
    [
62382718800,
62398447200,
62382704400,
62398432800,
-14400,
0,
'AST'
    ],
    [
62398447200,
62414168400,
62398436400,
62414157600,
-10800,
1,
'ADT'
    ],
    [
62414168400,
62429896800,
62414154000,
62429882400,
-14400,
0,
'AST'
    ],
    [
62429896800,
62445618000,
62429886000,
62445607200,
-10800,
1,
'ADT'
    ],
    [
62445618000,
62461346400,
62445603600,
62461332000,
-14400,
0,
'AST'
    ],
    [
62461346400,
62477067600,
62461335600,
62477056800,
-10800,
1,
'ADT'
    ],
    [
62477067600,
62492796000,
62477053200,
62492781600,
-14400,
0,
'AST'
    ],
    [
62492796000,
62508517200,
62492785200,
62508506400,
-10800,
1,
'ADT'
    ],
    [
62508517200,
62524245600,
62508502800,
62524231200,
-14400,
0,
'AST'
    ],
    [
62524245600,
62540571600,
62524234800,
62540560800,
-10800,
1,
'ADT'
    ],
    [
62540571600,
62555695200,
62540557200,
62555680800,
-14400,
0,
'AST'
    ],
    [
62555695200,
62572021200,
62555684400,
62572010400,
-10800,
1,
'ADT'
    ],
    [
62572021200,
62587749600,
62572006800,
62587735200,
-14400,
0,
'AST'
    ],
    [
62587749600,
62603470800,
62587738800,
62603460000,
-10800,
1,
'ADT'
    ],
    [
62603470800,
62619199200,
62603456400,
62619184800,
-14400,
0,
'AST'
    ],
    [
62619199200,
62634920400,
62619188400,
62634909600,
-10800,
1,
'ADT'
    ],
    [
62634920400,
62650648800,
62634906000,
62650634400,
-14400,
0,
'AST'
    ],
    [
62650648800,
62666370000,
62650638000,
62666359200,
-10800,
1,
'ADT'
    ],
    [
62666370000,
62680284000,
62666355600,
62680269600,
-14400,
0,
'AST'
    ],
    [
62680284000,
62697819600,
62680273200,
62697808800,
-10800,
1,
'ADT'
    ],
    [
62697819600,
62711733600,
62697805200,
62711719200,
-14400,
0,
'AST'
    ],
    [
62711733600,
62729874000,
62711722800,
62729863200,
-10800,
1,
'ADT'
    ],
    [
62729874000,
62743183200,
62729859600,
62743168800,
-14400,
0,
'AST'
    ],
    [
62743183200,
62761323600,
62743172400,
62761312800,
-10800,
1,
'ADT'
    ],
    [
62761323600,
62774632800,
62761309200,
62774618400,
-14400,
0,
'AST'
    ],
    [
62774632800,
62792773200,
62774622000,
62792762400,
-10800,
1,
'ADT'
    ],
    [
62792773200,
62806687200,
62792758800,
62806672800,
-14400,
0,
'AST'
    ],
    [
62806687200,
62824222800,
62806676400,
62824212000,
-10800,
1,
'ADT'
    ],
    [
62824222800,
62838136800,
62824208400,
62838122400,
-14400,
0,
'AST'
    ],
    [
62838136800,
62855672400,
62838126000,
62855661600,
-10800,
1,
'ADT'
    ],
    [
62855672400,
62869586400,
62855658000,
62869572000,
-14400,
0,
'AST'
    ],
    [
62869586400,
62887726800,
62869575600,
62887716000,
-10800,
1,
'ADT'
    ],
    [
62887726800,
62901036000,
62887712400,
62901021600,
-14400,
0,
'AST'
    ],
    [
62901036000,
62919176400,
62901025200,
62919165600,
-10800,
1,
'ADT'
    ],
    [
62919176400,
62932485600,
62919162000,
62932471200,
-14400,
0,
'AST'
    ],
    [
62932485600,
62950626000,
62932474800,
62950615200,
-10800,
1,
'ADT'
    ],
    [
62950626000,
62964540000,
62950611600,
62964525600,
-14400,
0,
'AST'
    ],
    [
62964540000,
62982075600,
62964529200,
62982064800,
-10800,
1,
'ADT'
    ],
    [
62982075600,
62995989600,
62982061200,
62995975200,
-14400,
0,
'AST'
    ],
    [
62995989600,
63013525200,
62995978800,
63013514400,
-10800,
1,
'ADT'
    ],
    [
63013525200,
63027439200,
63013510800,
63027424800,
-14400,
0,
'AST'
    ],
    [
63027439200,
63044974800,
63027428400,
63044964000,
-10800,
1,
'ADT'
    ],
    [
63044974800,
63058888800,
63044960400,
63058874400,
-14400,
0,
'AST'
    ],
    [
63058888800,
63077029200,
63058878000,
63077018400,
-10800,
1,
'ADT'
    ],
    [
63077029200,
63090338400,
63077014800,
63090324000,
-14400,
0,
'AST'
    ],
    [
63090338400,
63108478800,
63090327600,
63108468000,
-10800,
1,
'ADT'
    ],
    [
63108478800,
63121788000,
63108464400,
63121773600,
-14400,
0,
'AST'
    ],
    [
63121788000,
63139928400,
63121777200,
63139917600,
-10800,
1,
'ADT'
    ],
    [
63139928400,
63153842400,
63139914000,
63153828000,
-14400,
0,
'AST'
    ],
    [
63153842400,
63171378000,
63153831600,
63171367200,
-10800,
1,
'ADT'
    ],
    [
63171378000,
63185292000,
63171363600,
63185277600,
-14400,
0,
'AST'
    ],
    [
63185292000,
63202827600,
63185281200,
63202816800,
-10800,
1,
'ADT'
    ],
    [
63202827600,
63216741600,
63202813200,
63216727200,
-14400,
0,
'AST'
    ],
    [
63216741600,
63234882000,
63216730800,
63234871200,
-10800,
1,
'ADT'
    ],
    [
63234882000,
63248191200,
63234867600,
63248176800,
-14400,
0,
'AST'
    ],
    [
63248191200,
63266331600,
63248180400,
63266320800,
-10800,
1,
'ADT'
    ],
    [
63266331600,
63279640800,
63266317200,
63279626400,
-14400,
0,
'AST'
    ],
    [
63279640800,
63297781200,
63279630000,
63297770400,
-10800,
1,
'ADT'
    ],
    [
63297781200,
63309276000,
63297766800,
63309261600,
-14400,
0,
'AST'
    ],
    [
63309276000,
63329835600,
63309265200,
63329824800,
-10800,
1,
'ADT'
    ],
    [
63329835600,
63340725600,
63329821200,
63340711200,
-14400,
0,
'AST'
    ],
    [
63340725600,
63361285200,
63340714800,
63361274400,
-10800,
1,
'ADT'
    ],
    [
63361285200,
63372175200,
63361270800,
63372160800,
-14400,
0,
'AST'
    ],
    [
63372175200,
63392734800,
63372164400,
63392724000,
-10800,
1,
'ADT'
    ],
    [
63392734800,
63404229600,
63392720400,
63404215200,
-14400,
0,
'AST'
    ],
    [
63404229600,
63424789200,
63404218800,
63424778400,
-10800,
1,
'ADT'
    ],
    [
63424789200,
63435679200,
63424774800,
63435664800,
-14400,
0,
'AST'
    ],
    [
63435679200,
63456238800,
63435668400,
63456228000,
-10800,
1,
'ADT'
    ],
    [
63456238800,
63467128800,
63456224400,
63467114400,
-14400,
0,
'AST'
    ],
    [
63467128800,
63487688400,
63467118000,
63487677600,
-10800,
1,
'ADT'
    ],
    [
63487688400,
63498578400,
63487674000,
63498564000,
-14400,
0,
'AST'
    ],
    [
63498578400,
63519138000,
63498567600,
63519127200,
-10800,
1,
'ADT'
    ],
    [
63519138000,
63530028000,
63519123600,
63530013600,
-14400,
0,
'AST'
    ],
    [
63530028000,
63550587600,
63530017200,
63550576800,
-10800,
1,
'ADT'
    ],
    [
63550587600,
63561477600,
63550573200,
63561463200,
-14400,
0,
'AST'
    ],
    [
63561477600,
63582037200,
63561466800,
63582026400,
-10800,
1,
'ADT'
    ],
    [
63582037200,
63593532000,
63582022800,
63593517600,
-14400,
0,
'AST'
    ],
    [
63593532000,
63614091600,
63593521200,
63614080800,
-10800,
1,
'ADT'
    ],
    [
63614091600,
63624981600,
63614077200,
63624967200,
-14400,
0,
'AST'
    ],
    [
63624981600,
63645541200,
63624970800,
63645530400,
-10800,
1,
'ADT'
    ],
    [
63645541200,
63656431200,
63645526800,
63656416800,
-14400,
0,
'AST'
    ],
    [
63656431200,
63676990800,
63656420400,
63676980000,
-10800,
1,
'ADT'
    ],
    [
63676990800,
63687880800,
63676976400,
63687866400,
-14400,
0,
'AST'
    ],
    [
63687880800,
63708440400,
63687870000,
63708429600,
-10800,
1,
'ADT'
    ],
];

sub olson_version { '2008c' }

sub has_dst_changes { 46 }

sub _max_year { 2018 }

sub _new_instance
{
    return shift->_init( @_, spans => $spans );
}

sub _last_offset { -14400 }

my $last_observance = bless( {
  'format' => 'A%sT',
  'gmtoff' => '-4:00',
  'local_start_datetime' => bless( {
    'formatter' => undef,
    'local_rd_days' => 721354,
    'local_rd_secs' => 0,
    'offset_modifier' => 0,
    'rd_nanosecs' => 0,
    'tz' => bless( {
      'name' => 'floating',
      'offset' => 0
    }, 'DateTime::TimeZone::Floating' ),
    'utc_rd_days' => 721354,
    'utc_rd_secs' => 0,
    'utc_year' => 1977
  }, 'DateTime' ),
  'offset_from_std' => 0,
  'offset_from_utc' => -14400,
  'until' => [],
  'utc_start_datetime' => bless( {
    'formatter' => undef,
    'local_rd_days' => 721354,
    'local_rd_secs' => 14400,
    'offset_modifier' => 0,
    'rd_nanosecs' => 0,
    'tz' => bless( {
      'name' => 'floating',
      'offset' => 0
    }, 'DateTime::TimeZone::Floating' ),
    'utc_rd_days' => 721354,
    'utc_rd_secs' => 14400,
    'utc_year' => 1977
  }, 'DateTime' )
}, 'DateTime::TimeZone::OlsonDB::Observance' )
;
sub _last_observance { $last_observance }

my $rules = [
  bless( {
    'at' => '2:00',
    'from' => '2007',
    'in' => 'Mar',
    'letter' => 'D',
    'name' => 'US',
    'offset_from_std' => 3600,
    'on' => 'Sun>=8',
    'save' => '1:00',
    'to' => 'max',
    'type' => undef
  }, 'DateTime::TimeZone::OlsonDB::Rule' ),
  bless( {
    'at' => '2:00',
    'from' => '2007',
    'in' => 'Nov',
    'letter' => 'S',
    'name' => 'US',
    'offset_from_std' => 0,
    'on' => 'Sun>=1',
    'save' => '0',
    'to' => 'max',
    'type' => undef
  }, 'DateTime::TimeZone::OlsonDB::Rule' )
]
;
sub _rules { $rules }


1;
