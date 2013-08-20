# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 36 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/buildSelf.al)"
sub buildSelf {
	my $self = shift;
	my $prev = shift;

	if ($self->{_path} =~ s/\*$//) {
		$self->{_repeat} = 1;
	}

#	warn "Building from ", $self->{_path}, "\n";


	my @parts = split('/', $self->{_path});
	my @fullpath;
	$self->{Relative} = 0;

	if ($self->{_path} !~ /^\//) {
		# It's a relative path

		$self->{_relative} = 1;
		@fullpath = @{$prev->{_fullpath}};

		if ($prev->isRelative) {
			# prev was a relative path so remove top item
			pop @fullpath;
		}
		foreach ( @parts ) {
			if ($_ eq "..") {
				pop @fullpath;
			}
			else {
				push @fullpath, $_;
			}
		}
	}
	else {
		# remove crap from beginning (empty because of preceding "/")
		shift @parts;
		@fullpath = @parts;
	}

	if ($fullpath[$#fullpath] =~ /^\@(\w+)$/) {
		pop @fullpath;
		pop @parts;
		$self->{_attrib} = $1;
	}

	$self->{Parts} = \@parts;
	$self->{_fullpath} = \@fullpath;

#	warn "Built: ", $self->FullPath, "\n";

}

# end of CGI::XMLForm::Path::buildSelf
1;
