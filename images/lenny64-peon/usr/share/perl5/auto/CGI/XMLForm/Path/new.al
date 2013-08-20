# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 21 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/new.al)"
# This class allows comparison of current paths

sub new {
	my $proto = shift;
	my $class = ref($proto) || $proto;
	my $self;
	$self->{_path} = $_[0];
	$self->{_fullpath} = [];
	bless ($self, $class);          # reconsecrate
	if ($self->{_path}) {
		$self->buildSelf($_[1] || new $class);
	}
	return $self;
}

# end of CGI::XMLForm::Path::new
1;
