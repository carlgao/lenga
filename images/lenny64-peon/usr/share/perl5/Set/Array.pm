##############################################################################
# Set::Array
#
# See POD at end for documentation.
##############################################################################
package Set::Array;
use strict;
use attributes qw(reftype);
use subs qw(foreach pack push pop shift join rindex splice unpack unshift);
use Want;
use Carp;

# Some not documented/implemented.  Waiting for Want-0.06 to arrive.
use overload
   "=="  => "is_equal",
   "!="  => "not_equal",
   "+"   => "union",
   "&"   => "bag",
   "*"   => "intersection",
   "-"   => "difference",
   "%"   => "symmetric_difference",
   "<<"  => "push",
   ">>"  => "shift",
   "<<=" => "unshift",
   ">>=" => "pop",
   "fallback" => 1;

BEGIN{
   use vars qw($VERSION);
   $VERSION = '0.14';
}

sub new{
   my($class,@array) = @_;
   @array = @$class if !@array && ref($class);
   return bless \@array, ref($class) || $class;
}

# Turn array into a hash
sub as_hash{
   my($self,%arg) = @_;

   $arg{key_order} = 'even' unless $arg{key_order};

   if( (scalar(@$self) % 2) != 0 ){
      Carp::croak "Odd number of elements in 'as_hash()' call";
   }
   else{
      my %hash;
      if($arg{key_order} eq 'odd'){ %hash = CORE::reverse(@$self) }
      else{ %hash = @$self }
      if(want('OBJECT')){ return $self } # This shouldn't happen
      return %hash if wantarray;
      return \%hash;
   }
}
*to_hash = \&as_hash;

# Return element at specified index
sub at{
   my($self,$index) = @_;
   if(want('OBJECT')){ return bless \${$self}[$index] }
   return @$self[$index];
}

# Delete (or undef) contents of array
sub clear{
   my($self,$undef) = @_;
   if($undef){ @{$self} = map{ undef } @{$self} }
   else{ @{$self} = () }

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} }
}

# Remove all undef elements
sub compact{
   my($self) = @_;

   if( (want('OBJECT')) || (!defined wantarray) ){
      @$self = grep defined $_, @$self;
      return $self;
   }

   my @temp;
   CORE::foreach(@{$self}){ CORE::push(@temp,$_) if defined $_ }
   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Return the number of times the specified value appears within array
sub count{
   my($self,$val) = @_;

   my $hits = 0;

   # Count undefined elements
   unless(defined($val)){
      foreach(@$self){ $hits++ unless $_ }
      if(want('OBJECT')){ return bless \$hits }
      return $hits;
   }

   $hits = grep /^$val$/, @$self;
   if(want('OBJECT')){ return bless \$hits }
   return $hits;
}

# Delete all instances of the specified value within the array
sub delete{
   my($self,@vals) = @_;

   unless(defined($vals[0])){
      Carp::croak "Undefined value passed to 'delete()' method";
   }

   foreach my $val(@vals){
      @$self = grep $_ !~ /^$val$/, @$self;
   }

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} }
}

# Deletes an element at a specified index, or range of indices
# I'm not sure I like the range behavior for this method and may change it
# (or remove it) in the future.
sub delete_at{
   my($self,$start_index, $end_index) = @_;

   unless(defined($start_index)){
      Carp::croak "No index passed to 'delete_at()' method";
   }

   unless(defined($end_index)){ $end_index = 0 }
   if( ($end_index eq 'end') || ($end_index == -1) ){ $end_index = $#$self }

   my $num = ($end_index - $start_index) + 1;

   CORE::splice(@{$self},$start_index,$num);

   if(want('OBJECT') || !(defined wantarray)){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} }
}

# Returns a list of duplicate items in the array.
sub duplicates{
   my($self) = @_;

   my(@dups,%count);

   if(want('OBJECT') || !(defined wantarray)){
      my %count;
      CORE::foreach(@$self){
         $count{$_}++;
         CORE::push(@dups,$_) if $count{$_} > 1;
      }
      @$self = @dups;
      return $self;
   }

   CORE::foreach(@$self){
      $count{$_}++;
      if($count{$_} > 1){ CORE::push(@dups,$_) }
   }

   if(wantarray){ return @dups }
   if(defined wantarray){ return \@dups }
}

# Tests to see if value exists anywhere within array
sub exists{
   my($self,$val) = @_;

   # Check specifically for undefined values
   unless(defined($val)){
      foreach(@$self){ unless($_){ return 1 } }
      return 0;
   }

   if(grep /^$val$/, @$self){ return 1 }

   return 0;
}

*contains = \&exists;

# Fills the elements of the array.  Does not create new elements
sub fill{
   my($self,$val, $start, $length) = @_;  # Start may also be a range
   return unless(scalar(@{$self}) > 0);   # Test for empty array

   unless(defined($start)){ $start = 0 }

   if($length){ $length += $start }
   else{ $length = $#$self + 1}

   if($start =~ /^(\d)\.\.(\d)$/){
      CORE::foreach($1..$2){ @{$self}[$_] = $val }
      return $self;
   }

   CORE::foreach(my $n=$start; $n<$length; $n++){ @{$self}[$n] = $val }

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} }
}

# Returns the first element of the array
sub first{
   my($self) = @_;
   if(want('OBJECT')){ return bless \@{$self}[0] }
   return @{$self}[0];
}

# Flattens any list references into a plain list
sub flatten{
   my($self) = @_;

   if( (want('OBJECT')) || (!defined wantarray) ){
      for(my $n=0; $n<=$#$self; $n++){
	 if( ref($$self[$n]) eq 'ARRAY' ){
	    CORE::splice(@$self,$n,1,@{$$self[$n]});
	    $n--;
	    next;
	 }
         if( ref($$self[$n]) eq 'HASH' ){
            CORE::splice(@$self,$n,1,%{$$self[$n]});
            --$n;
	    next;
         }
      }
      return $self
   }

   my @temp = @$self;
   for(my $n=0; $n<=$#temp; $n++){
      if( ref($temp[$n]) eq 'ARRAY' ){
         CORE::splice(@temp,$n,1,@{$temp[$n]});
         $n--;
         next;
      }
      if( ref($temp[$n]) eq 'HASH' ){
         CORE::splice(@temp,$n,1,%{$temp[$n]});
         --$n;
         next;
      }
   }
   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Loop mechanism
sub foreach{
   my($self,$coderef) = @_;

   unless(ref($coderef) eq 'CODE'){
      Carp::croak "Invalid code reference passed to 'foreach' method";
   }

   CORE::foreach (@$self){ &$coderef }

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} }
}

# Append or prepend a string to each element of the array
sub impose{
   my($self,$placement,$string) = @_;

   # Set defaults
   unless($placement =~ /\bappend\b|\bprepend\b/i){
      $string = $placement;
      $placement = 'append';
   }

   unless(CORE::defined($string)){
      Carp::croak "No string supplied to 'impose()' method";
   }

   if(want('OBJECT') or !(defined wantarray)){
      if($placement =~ /append/){ foreach(@$self){ $_ = $_ . $string } }
      if($placement =~ /prepend/){ foreach(@$self){ $_ = $string . $_ } }
      return $self;
   }

   my @copy = @$self;
   if($placement =~ /append/){ foreach(@copy){ $_ = $_ . $string } }
   if($placement =~ /prepend/){ foreach(@copy){ $_ = $string . $_ } }

   if(wantarray){ return @copy }
   if(defined wantarray){ return \@copy }
}

# Returns the index of the first occurrence within the array
# of the specified value
sub index{
   my($self,$val) = @_;

   # Test for undefined value
   unless(defined($val)){
      for(my $n=0; $n<=$#$self; $n++){
         unless($self->[$n]){
            if(want('OBJECT')){ return bless \$n }
            if(defined wantarray){ return $n }
         }
      }
   }

   for(my $n=0; $n<=$#$self; $n++){
      next unless defined $self->[$n];
      if( $self->[$n] =~ /$val/ ){
         if(want('OBJECT')){ return bless \$n }
         if(defined wantarray){ return $n }
      }
   }
   return undef;
}

# Given an index, or range of indices, returns the value at that index
# (or a list of values for a range).
sub indices{
   my($self,@indices) = @_;
   my @iArray;

   unless(defined($indices[0])){
      Carp::croak "No index/indices passed to 'indices' (aka 'get') method";
   }

   CORE::foreach(@indices){
      if($_ =~ /(\d)\.\.(\d)/){ for($1..$2){
         CORE::push(@iArray,@{$self}[$_]) };
         next;
      }
      if(@{$self}[$_]){ CORE::push(@iArray,@{$self}[$_]) }
      else{ CORE::push(@iArray,undef) }
   }

   if(scalar(@iArray) == 1){
      if(want('OBJECT')){ return bless \$iArray[0] }
      return $iArray[0];
   }

   if(want('OBJECT')){ return bless \@iArray }
   if(wantarray){ return @iArray }
   if(defined wantarray){ return \@iArray }
}

# Alias for 'indices()'
*get = \&indices;

# Tests to see if array contains any elements
sub is_empty{
   my($self) = @_;
   if( (scalar @{$self}) > 0){ return 0 }
   return 1;
}

# Set a specific index to a specific value
sub set{
   my($self,$index,$val) = @_;

   unless(defined($index) && $val){
      Carp::croak "No index or value passed to 'set()' method";
   }

   if(want('OBJECT')){
      $self->[$index] = $val;
      return $self;
   }

   my @copy = @$self;
   $copy[$index] = $val;

   if(wantarray){ return @copy }
   if(defined wantarray){ return \@copy }
}

# Joins the contents of the list with the specified character
sub join{
   my($self,$char) = @_;

   $char = ',' unless $char;

   my $string;

   if(want('OBJECT')){
      $string = CORE::join($char,@$self);
      return bless \$string;
   }

   $string = CORE::join($char,@$self);
   return $string;
}

# Returns the last element of the array
sub last{
   my($self) = @_;
   if(want('OBJECT')){ return bless \@{$self}[-1] }
   return @$self[-1];
}

# Returns the number of elements within the array
sub length{
   my($self) = @_ ;
   my $length = scalar(@$self);
   if(want('OBJECT')){ return bless \$length }
   return $length;
}

# Returns the maximum numerical value in the array
sub max{
   my($self) = @_;
   my $max;

   no warnings 'uninitialized';
   CORE::foreach(@{$self}){ $max = $_ if $_ > $max }

   if(want('OBJECT')){ return bless \$max }
   return $max;
}

sub pack{
   my($self,$template) = @_;

   Carp::croak "No template provided to 'pack()' method" unless $template;

   if(want('OBJECT') || !(defined wantarray)){
      $self->[0] = CORE::pack($template, @$self);
      $#$self = 0;
      return $self;
   }

   return CORE::pack($template,@$self);
}

# Pops and returns the last element off the array
sub pop{
   my($self) = @_;
   my $popped = CORE::pop(@$self);
   if(want('OBJECT')){ return bless \$popped }
   return $popped;
}

# Prints the contents of the array as a flat list. Optional newline
sub print{
   my($self,$nl) = @_;

   if(reftype($self) eq 'ARRAY'){
      if(wantarray){ return @$self }
      if(defined wantarray){ return \@{$self} }
      print @$self;
      if($nl){ print "\n" }
   }
   elsif(reftype($self) eq 'SCALAR'){
      if(defined wantarray){ return $$self }
      print $$self;
      if($nl){ print "\n" }
   }
   else{
      print @$self;
      if($nl){ print "\n" }
   }

   return $self;
}

# Pushes an element onto the end of the array
sub push{
   my($self,@list) = @_;

   CORE::push(@{$self},@list);

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} };
}

# Randomizes the order of the contents of the array
# Taken from "The Perl Cookbook"
sub randomize{
   my($self) = @_;
   my($i,$ref,@temp);

   unless( (want('OBJECT')) || (!defined wantarray) ){
      @temp = @{$self};
      $ref = \@temp;
   }
   else{ $ref = $self }

   for($i = @$ref; --$i; ){
      my $j = int rand ($i+1);
      next if $i == $j;
      @$ref[$i,$j] = @$ref[$j,$i];
   }

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Reverses the contents of the array
sub reverse{
   my($self) = @_;

   if( (want('OBJECT')) || (!defined wantarray) ){
      @$self = CORE::reverse @$self;
      return $self;
   }

   my @temp = CORE::reverse @$self;
   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Same as index, except that it returns the position of the
# last occurrence, instead of the first.
sub rindex{
   my($self,$val) = @_;

   # Test for undefined value
   unless(defined($val)){
      for(my $n = $#$self; $n >= 0; $n--){
         unless($self->[$n]){
            if(want('OBJECT')){ return bless \$n }
            if(defined wantarray){ return $n }
         }
      }
   }

   for(my $n = $#$self; $n >= 0; $n--){
      next unless defined $self->[$n];
      if( $self->[$n] =~ /$val/ ){
         if(want('OBJECT')){ return bless \$n }
         if(defined wantarray){ return $n }
      }
   }
   return undef;

}

# Moves the last element of the array to the front, or vice-versa
sub rotate{
   my($self,$dir) = @_;

   if( (want('OBJECT')) || (!defined wantarray) ){
      unless(defined($dir) && $dir eq 'ftol'){
         CORE::unshift(@$self, CORE::pop(@$self));
         return $self;
      }
      CORE::push(@$self,CORE::shift(@$self));
      return $self;
   }

   my @temp = @$self;
   unless(defined($dir) && $dir eq 'ftol'){
      CORE::unshift(@temp, CORE::pop(@temp));
      if(wantarray){ return @temp }
      if(defined wantarray){ return \@temp }
   }
   CORE::push(@temp,CORE::shift(@temp));
   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Shifts and returns the first element off the array
sub shift{
   my($self) = @_;
   my $shifted = CORE::shift @$self;
   if(want('OBJECT')){ return bless \$shifted }
   return $shifted;
}

# Sorts the array alphabetically.
sub sort{
   my($self,$coderef) = @_;

   if($coderef){

      # Complements of Sean McAfee
      my $caller = caller();
      local(*a,*b) = do{
         no strict 'refs';
         (*{"${caller}::a"},*{"${caller}::b"});
      };

      if( (want('OBJECT')) || (!defined wantarray) ){
         @$self = CORE::sort $coderef @$self;
         return $self;
      }

      my @sorted = CORE::sort $coderef @$self;
      if(wantarray){ return @sorted }
      if(defined wantarray){ return \@sorted }
   }
   else{
      if( (want('OBJECT')) || (!defined wantarray) ){
         @$self = CORE::sort @$self;
         return $self;
      }
      my @sorted = CORE::sort @$self;
      if(wantarray){ return @sorted }
      if(defined wantarray){ return \@sorted }
   }
}

# Splices a value, or range of values, from the array
sub splice{
   my($self,$offset,$length,@list) = @_;

   no warnings 'uninitialized';

   my @deleted;
   unless(defined($offset)){
      @deleted = CORE::splice(@$self);
      if(want('OBJECT')){ return $self }
      if(wantarray){ return @deleted }
      if(defined wantarray){ return \@deleted }
   }
   unless(defined($length)){
      @deleted = CORE::splice(@$self,$offset);
      if(want('OBJECT')){ return $self }
      if(wantarray){ return @deleted }
      if(defined wantarray){ return \@deleted }
   }
   unless(defined($list[0])){
      @deleted = CORE::splice(@$self,$offset,$length);
      if(want('OBJECT')){ return $self }
      if(wantarray){ return @deleted }
      if(defined wantarray){ return \@deleted }
   }

   @deleted = CORE::splice(@$self,$offset,$length,@list);
   if(want('OBJECT')){ return $self }
   if(wantarray){ return @deleted }
   if(defined wantarray){ return \@deleted }
}

# Returns a list of unique items in the array
sub unique{
   my($self,$nc) = @_;

   my %item;

   CORE::foreach(@$self){ $item{$_}++ }

   if(want('OBJECT') || !(defined wantarray)){
      @$self = keys %item;
      %item = ();
      return $self;
   }

   my @temp = keys %item;
   %item = ();

   if(wantarray){ return @temp }
   if(defined wantarray){ return \@temp }
}

# Unshifts a value to the front of the array
sub unshift{
   my($self,@list) = @_;
   CORE::unshift(@$self,@list);

   if(want('OBJECT')){ return $self }
   if(wantarray){ return @$self }
   if(defined wantarray){ return \@{$self} };
}

#### OVERLOADED OPERATOR METHODS ####

# Really just a 'push', but needs to handle ops
sub append{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   CORE::push(@{$op1},@{$op2});

   if(want('OBJECT')){ return $op1 }
   return @$op1 if wantarray;
   return \@{$op1} if defined wantarray;
}

# A union that includes non-unique values (i.e. everything)
sub bag{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   if(want('OBJECT') || !(defined wantarray)){
      CORE::push(@$op1,@$op2);
      return $op1;
   }
   my @copy = (@$op1,@$op2);
   return @copy if wantarray;
   return \@copy if defined wantarray;
}

# Needs work
sub complement{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%item1,%item2,@comp);
   CORE::foreach(@$op1){ $item1{$_}++ }
   CORE::foreach(@$op2){ $item2{$_}++ }

   CORE::foreach(keys %item2){
      if($item1{$_}){ next }
      CORE::push(@comp,$_);
   }

   if(want('OBJECT')){ return bless \@comp }
   if(wantarray){ return @comp }
   if(defined wantarray){ return \@comp }
}

# Returns elements in left set that are not in the right set
sub difference{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%item1,%item2,@diff);
   CORE::foreach(@$op1){ $item1{$_}=$_ }
   CORE::foreach(@$op2){ $item2{$_}=$_ }

   CORE::foreach(keys %item1){
      if(exists $item2{$_}){ next }
      CORE::push(@diff,$item1{$_});
   }

   if(want('OBJECT') || !(defined wantarray)){
      @$op1 = @diff;
      return $op1;
   }

   if(wantarray){ return @diff }
   if(defined wantarray){ return \@diff }
}

# Returns the elements common to both arrays
sub intersection{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%count,@int);
   @count{@$op1} = (1) x @$op1;

   if(want('OBJECT') || !(defined wantarray)){
      @$op1 = CORE::grep{CORE::delete $count{$_}} @$op2;
      return $op1;
   }

   @int = CORE::grep{CORE::delete $count{$_}} @$op2;
   if(wantarray){ return @int }
   if(defined wantarray){ return \@int }
}

# Tests to see if arrays are equal (regardless of order)
sub is_equal{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%count1, %count2);

   if(scalar(@$op1) != scalar(@$op2)){ return 0 }

   CORE::foreach(@$op1){ $count1{$_}++ }
   CORE::foreach(@$op2){ $count2{$_}++ }

   CORE::foreach my $key(keys %count1){
      return 0 unless CORE::defined($count1{$key});
      return 0 unless CORE::defined($count2{$key});
      if($count1{$key} ne $count2{$key}){ return 0 }
   }
   return 1;
}

# Tests to see if arrays are not equal (order ignored)
sub not_equal{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%count1, %count2);

   if(scalar(@$op1) != scalar(@$op2)){ return 1 }

   CORE::foreach(@$op1){ $count1{$_}++ }
   CORE::foreach(@$op2){ $count2{$_}++ }

   CORE::foreach my $key(keys %count1){
      return 1 unless CORE::defined($count1{$key});
      return 1 unless CORE::defined($count2{$key});
      if($count1{$key} ne $count2{$key}){ return 1 }
   }
   return 0;
}

# Returns elements in one set or the other, but not both
sub symmetric_difference{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my(%count1,%count2,%count3,@symdiff);
   @count1{@$op1} = (1) x @$op1;
   @count2{@$op2} = (1) x @$op2;

   CORE::foreach(CORE::keys %count1,CORE::keys %count2){ $count3{$_}++ }

   if(want('OBJECT') || !(defined wantarray)){
      @$op1 = CORE::grep{$count3{$_} == 1} CORE::keys %count3;
      return $op1;
   }

   @symdiff = CORE::grep{$count3{$_} == 1} CORE::keys %count3;
   if(wantarray){ return @symdiff }
   if(defined wantarray){ return \@symdiff }
}

*sym_diff = \&symmetric_difference;

# Returns the union of two arrays, non-unique values excluded
sub union{
   my($op1, $op2, $reversed) = @_;
   ($op2,$op1) = ($op1,$op2) if $reversed;

   my %union;
   CORE::foreach(@$op1, @$op2){ $union{$_}++ }

   if(want('OBJECT') || !(defined wantarray)){
      @$op1 = CORE::keys %union;
      return $op1;
   }

   my @union = CORE::keys %union;

   if(wantarray){ return @union }
   if(defined wantarray){ return \@union }
}
1;
__END__

=head1 NAME

Set::Array - Arrays as objects with lots of handy methods (including Set
comparisons) and support for method chaining.

=head1 SYNOPSIS

C<< my $sao1 = Set::Array->new(1,2,4,"hello",undef); >>

C<< my $sao2 = Set::Array->new(qw(a b c a b c)); >>

C<< print $sao1->length; # prints 5 >>

C<< $sao2->unique->length->print; # prints 3 >>

=head1 PREREQUISITES

Perl 5.6 or later

The 'Want' module by Robin Houston.  Available on CPAN.

=head1 DESCRIPTION

Set::Array allows you to create arrays as objects and use OO-style methods
on them.  Many convenient methods are provided here that appear in the FAQ's,
the Perl Cookbook or posts from comp.lang.perl.misc.
In addition, there are Set methods with corresponding (overloaded)
operators for the purpose of Set comparison, i.e. B<+>, B<==>, etc.

The purpose is to provide built-in methods for operations that people are
always asking how to do, and which already exist in languages like Ruby.  This
should (hopefully) improve code readability and/or maintainability.  The
other advantage to this module is method-chaining by which any number of
methods may be called on a single object in a single statement.


=head1 OBJECT BEHAVIOR

The exact behavior of the methods depends largely on the calling context.

B<Here are the rules>:

* If a method is called in void context, the object itself is modified.

* If the method called is not the last method in a chain (i.e. it's called
  in object context), the object itself is modified by that method regardless
  of the 'final' context or method call.

* If a method is called in list or scalar context, a list or list refererence
  is returned, respectively. The object itself is B<NOT> modified.

Here's a quick example:

C<< my $sao = Set::Array->new(1,2,3,2,3); >>

C<< my @uniq = $sao->unique(); # Object unmodified.  '@uniq' contains 3 values. >>

C<< $sao->unique(); # Object modified, now contains 3 values >>

B<Here are the exceptions>:

* Methods that report a value, such as boolean methods like I<exists()> or
  other methods such as I<at()> or I<as_hash()>, never modify the object.

* The methods I<clear()>, I<delete()>, I<delete_at()>, and I<splice> will
  B<always> modify the object. It seemed much too counterintuitive to call these
  methods in any context without actually deleting/clearing/substituting the items!

* The methods I<shift()> and I<pop()> will modify the object B<AND> return
  the value that was shifted or popped from the array.  Again, it seemed
  much too counterintuitive for something like C<$val = $sao-E<gt>shift> to
  return a value while leaving the object's list unchanged.  If you
  really want the first or last value without modifying the object, you
  can always use the I<first()> or I<last()> method, respectively.

* The I<join()> method always returns a string and is really meant for use
  in conjunction with the I<print()> method.

=head1 BOOLEAN METHODS

B<exists(>I<val>B<)> - Returns 1 if I<val> exists within the array,
0 otherwise.  If no value (or I<undef>) is passed, then this
method will test for the existence of undefined values within the array.

B<is_empty()> - Returns 1 if the array is empty, 0 otherwise.  Empty is
defined as having a length of 0.

=head1 STANDARD METHODS

B<at(>I<index>B<)> - Returns the item at the given index (or
I<undef>). A negative index may be used to count from the end of the array.
If no value (or I<undef>) is specified, it will look for the first item
that is not defined.

B<clear()> - Empties the array (i.e. length becomes 0).  You may
pass a '1' to this method to set each element of the array to I<undef> rather
than truly empty it.

B<compact()> - Removes undefined elements from the array.

B<count(>I<?val?>B<)> - Returns the number of instances of I<val>
within the array.  If I<val> is not specified (or is I<undef>), the
method will return the number of undefined values within the array.

B<delete(>I<list>B<)> - Deletes all items within I<list> from the array
that match.  This method will crash if I<list> is not defined.  If your goal
is to delete undefined values from your object, use the I<compact()>
method instead.

B<delete_at(>I<index, ?index?>B<)> - Deletes the item at the
specified index. If a second index is specified, a range of items is deleted.
You may use -1 or the string 'end' to refer to the last element of the array.

B<duplicates> - Returns a list of N-1 elements for each element N in the
set.  For example, if you have set "X X Y Y Y", this method would return
a the list "X Y Y".

B<fill(>I<val,?start?,?length?>B<)> - Sets the selected elements of
the array (which may be the entire array) to I<val>.  The default value for
start is 0. If length is not specified the entire array, however long it may
be at the time of the call, will be filled. Alternatively, a quoted integer
range may be used.

e.g. C<< $sao->fill('x','3-5'); >>

The array length/size may not be expanded with this call - it is only meant to
fill in already-existing elements.

B<first()> - Returns the first element of the array (or undef).

B<flatten()> - Causes a one-dimensional flattening of the array,
recursively. That is, for every element that is an array (or hash, or
a ref to either an array or hash), extract its elements into the array.

e.g. C<< my $sa = Set::Array-E<gt>new([1,3,2],{one=>'a',two=>'b'},x,y,z); >>

C<< $sao-E<gt>flatten->join(',')->print; # prints "1,3,2,one,a,two,b,x,y,z" >>

B<foreach(>I<sub ref>B<)> - Iterates over an array, executing
the subroutine for each element in the array.  If you wish to modify or
otherwise act directly on the contents of the array, use B<$_> within
your sub reference.

e.g. To increment all elements in the array by one...

C<< $sao-E<gt>foreach(sub{ ++$_ }); >>

B<get> - Alias for the B<indices()> method.

B<index(>I<val>B<)> - Returns the index of the first element of the array
object that contains I<val>.  Returns I<undef> if no value is found.

Note that there is no dereferencing here so if you're looking for an item
nested within a ref, use the I<flatten> method first.

B<indices(>I<val1,?val2?, ?val...?>B<)> - Returns an array
consisting of the elements at the specified indices or I<undef> if the element
is out of range.

A range may also be used.  It must be a quoted string in '0..3' format.

B<join(>I<?char?>B<)> - Joins the individual elements of the list into
a single string with the elements separated by the value of I<char>.  Useful
in conjunction with the I<print()> method.  If no character is specified,
then I<char> defaults to a comma.

e.g. C<< $sao-E<gt>join('-')-E<gt>print; >>

B<last()> - Returns the last element of the array (or I<undef>).

B<length()> - Returns the number of elements within the array.

B<max()> - Returns the maximum value of an array.  No effort is
made to check for non-numeric data.

B<pack(>I<template>B<)> - Packs the contents of the array into a
string (in scalar context) or a single array element (in object
or void context).

B<pop()> - Removes the last element from the array.  Returns the
popped element.

B<print(>I<?1?>B<)> - Prints the contents of the array. If a '1'
is provided as an argument, the output will automatically be terminated
with a newline.

This also doubles as a 'contents' method, if you just want to make a copy
of the array, e.g. my @copy = $sao-E<gt>print;

Can be called in void or list context, e.g.

C<< $sao->print(); # or... >>
C<< print "Contents of array are: ", $sao->print(); >>

B<push(>I<list>B<)> - Adds I<list> to the end of the array, where
I<list> is either a scalar value or a list.  Returns an array or array
reference in list or scalar context, respectively.  Note that it does
B<not> return the length in scalar context.  Use the I<length> method for that.

B<reverse()> - Reverses the order of the contents of the array.

B<rindex(>I<val>B<)> - Similar to the 'index()' method, except that it
returns the index of the last I<val> found within the array.

B<set(>I<index>,I<value>B<)> - Sets the element at I<index> to I<value>,
replacing whatever may have already been there.

B<shift()> - Shifts the first element of the array and returns
the shifted element.

B<sort(>I<?coderef?>B<)> - Sorts the contents of the array in alphabetical
order, or in the order specified by the optional I<coderef>.  Use your
standard I<$a> and I<$b> variables within your calling program, e.g:

C<< my $sao = Set::Array->new(
   { name => 'Berger', salary => 20000 },
   { name => 'Berger', salary => 15000 },
   { name => 'Vera', salary => 25000 },
); >>

C<< my $subref = sub{ $b->{name} cmp $a->{name} || $b->{salary} <=> $a->{salary} }; >>

C<< $sao14->sort($subref)->flatten->join->print(1); >>

B<splice(>I<?offset?,?length?,?list?>B<)> - Splice the array starting
at position I<offset> up to I<length> elements, and replace them with I<list>.
If no list is provided, all elements are deleted.  If length is omitted,
everything from I<offset> onward is removed.

Returns an array or array ref in list or scalar context, respectively.  This
method B<always> modifies the object, regardless of context.  If your goal was
to grab a range of values without modifying the object, use the I<indices>
method instead.

B<unique()> - Removes/returns non-unique elements from the list.

B<unshift(>I<list>B<)> - Prepends a scalar or list to array.  Note that
this method returns an array or array reference in list or scalar context,
respectively.  It does B<not> return the length of the array in scalar context.
Use the I<length> method for that.

=head1 ODDBALL METHODS

B<as_hash()> - Returns a hash based on the current array, with each
even numbered element (including 0) serving as the key, and each odd element
serving as the value.  This can be switched by using the I<key_order> option
and setting it to 'odd', in which case the even values serve as the values,
and the odd elements serve as the keys. The default is I<even>.

Of course, if you don't care about insertion order, you could just as well
do something like, C<$sao->reverse->as_hash;>

Carp::croak's if the array contains an odd number of elements.  This method does
not actually modify the object itself in any way.  It just returns a plain
hash in list context or a hash reference in scalar context.  The reference
is not blessed, therefore if this method is called as part of a chain, it
must be the last method called.

B<impose(>I<?append/prepend?>,I<string>B<)> - Appends or prepends the
specified string to each element in the array.  Specify the method by
using either the keyword 'append' or 'prepend'.  The default is 'append'.

B<randomize()> - Randomizes the order of the elements within the
array.

B<rotate(>I<direction>B<)> - Moves the last item of the list to the
front and shifts all other elements one to the right, or vice-versa, depending
on what you pass as the direction - 'ftol' (first to last) or 'ltof' (last to
first).  The default is 'ltof'.

e.g.
my $sao = Set::Array-E<gt>new(1,2,3);

$sao->rotate(); # order is now 3,1,2

$sao->rotate('ftol'); # order is back to 1,2,3

=head1 OVERLOADED (COMPARISON) OPERATORS

=head2 General Notes

For overloaded operators you may pass a Set::Array object, or just a normal
array reference (blessed or not) in any combination, so long as one is a
Set::Array object.  You may use either the operator or the equivalent method
call.

Examples (using the '==' operator or 'is_equal' method):

my $sao1 = Set::Array->new(1,2,3,4,5);

my $sao2 = Set::Array->new(1,2,3,4,5);

my $ref1 = [1,2,3,4,5];

if($sao1 == $sao2)...         # valid

if($sao1 == $ref1)...         # valid

if($ref1 == $sao2)...         # valid

if($sao1->is_equal($sao2))... # valid

if($sao1->is_equal($ref1))... # valid

All of these operations return either a boolean value (for equality operators) or
an array (in list context) or array reference (in scalar context).

B<&> or B<bag> - The union of both sets, including duplicates.

B<-> or B<difference> - Returns all elements in the left set that are not in
the right set.

B<==> or B<is_equal> - This tests for equality of the content of the sets,
though ignores order. Thus, comparing (1,2,3) and (3,1,2) will yield a I<true>
result.

B<!=> or B<not_equal> - Tests for inequality of the content of the sets.  Again,
order is ignored.

B<*> or B<intersection> - Returns all elements that are common to both sets.

B<%> or B<symmetric_difference> - Returns all elements that are in one set
or the other, but not both.  Opposite of intersection.

B<+> or B<union> - Returns the union of both sets.  Duplicates excluded.

=head1 EXAMPLES

For our examples, I'll create 3 different objects

my $sao1 = Set::Array->new(1,2,3,a,b,c,1,2,3);

my $sao2 = Set::Array->new(1,undef,2,undef,3,undef);

my $sao3 = Set::Array->new(1,2,3,['a','b','c'],{name=>"Dan"});

B<How do I...>

I<get the number of unique elements within the array?>

C<$sao1-E<gt>unique()-E<gt>length();>

I<count the number of non-undef elements within the array?>

C<$sao2-E<gt>compact()-E<gt>length();>

I<count the number of unique elements within an array, excluding undef?>

C<$sao2-E<gt>compact()-E<gt>unique()-E<gt>length();>

I<print a range of indices?>

C<$sao1-E<gt>indices('0..2')-E<gt>print();>

I<test to see if two Set::Array objects are equal?>

C<if($sao1 == $sao2){ ... }>

C<if($sao1-E<gt>is_equal($sao2){ ... } # Same thing>

I<fill an array with a value, but only if it's not empty?>

C<if(!$sao1-E<gt>is_empty()){ $sao1-E<gt>fill('x') }>

I<shift an element off the array and return the shifted value?>

C<my $val = $sao1-E<gt>shift())>

I<shift an element off the array and return the array?>

C<my @array = $sao1-E<gt>delete_at(0)>

I<flatten an array and return a hash based on now-flattened array?, with odd
elements as the key?>

C<my %hash = $sao3-E<gt>flatten()-E<gt>reverse-E<gt>as_hash();>

I<delete all elements within an array?>

C<$sao3-E<gt>clear();>

C<$sao3-E<gt>splice();>

I<modify the object AND assign a value at the same time?>

C<my @unique = $sao1-E<gt>unique-E<gt>print;>

=head1 KNOWN BUGS

There is a bug in the I<Want-0.05> module that currently prevents the use of
most of the overloaded operators, though you can still use the corresponding
method names.  The equality operators B<==> and B<!=> should work, however.

=head1 FUTURE PLANS

Anyone want a built-in 'permute()' method?

I'm always on the lookout for faster algorithms.  If you've looked at the code
for a particular method and you know of a faster way, please email me.  Be
prepared to backup your claims with benchmarks (and the benchmark code you
used).  Tests on more than one operating system are preferable.  No, I<map> is
not always faster - I<foreach> loops usually are in my experience.

More flexibility with the foreach method (perhaps with iterators?).

More tests.

=head1 THANKS

Thanks to all the kind (and sometimes grumpy) folks at comp.lang.perl.misc who
helped me with problems and ideas I had.

Thanks also to Robin Houston for the 'Want' module!  Where would method
chaining be without it?

=head1 AUTHOR

Original author: Daniel Berger
djberg96 at hotmail dot com
imperator on IRC (freenode)

Maintainer since V 0.12: Ron Savage <ron@savage.net.au>

Home page: http://savage.net.au/index.html

=cut
