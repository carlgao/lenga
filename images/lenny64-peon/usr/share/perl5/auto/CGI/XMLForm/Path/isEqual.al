# NOTE: Derived from blib/lib/CGI/XMLForm/Path.pm.
# Changes made here will be lost when autosplit is run again.
# See AutoSplit.pm.
package CGI::XMLForm::Path;

#line 125 "blib/lib/CGI/XMLForm/Path.pm (autosplit into blib/lib/auto/CGI/XMLForm/Path/isEqual.al)"
sub isEqual {
	my $self = shift;
	my $compare = shift;

	my @a = @{$self->{_fullpath}};
	my @b = @{$compare->{_fullpath}};

#	warn "Comparing: ", $self->FullPath, "\nTo      : ", $compare->FullPath,
#	"\n";
	if (scalar @a != scalar @b) {
		return 0;
	}
	foreach (0..$#a) {
		$a[$_] =~ s/\[.*\]//;
		$b[$_] =~ s/\[.*\]//;
		if ($a[$_] ne $b[$_]) {
			return 0;
		}
	}
#	warn "*** FOUND ***\n";
	return 1;
}

# end of CGI::XMLForm::Path::isEqual
1;
