# Copyrights 2001-2008 by Mark Overmeer.
#  For other contributors see ChangeLog.
# See the manual pages for details on the licensing terms.
# Pod stripped from pm file by OODoc 1.04.
use strict;
use warnings;

package Mail::Transport::Sendmail;
use vars '$VERSION';
$VERSION = '2.082';

use base 'Mail::Transport::Send';

use Carp;


sub init($)
{   my ($self, $args) = @_;

    $args->{via} = 'sendmail';

    $self->SUPER::init($args) or return;

    $self->{MTS_program}
      = $args->{proxy}
     || $self->findBinary('sendmail')
     || return;

    $self->{MTS_opts} = $args->{sendmail_options} || [];
    $self;
}

#------------------------------------------


sub trySend($@)
{   my ($self, $message, %args) = @_;

    my $program = $self->{MTS_program};
    if(open(MAILER, '|-')==0)
    {   my $options = $args{sendmail_options} || [];

        # {} to avoid warning
        { exec $program, '-ti', @{$self->{MTS_opts}}, @$options; }

        $self->log(NOTICE => "Errors when opening pipe to $program: $!");
        exit 1;
    }
 
    $self->putContent($message, \*MAILER, undisclosed => 1);

    unless(close MAILER)
    {   $self->log(NOTICE => "Errors when closing sendmail mailer $program: $!");
        $? ||= $!;
        return 0;
    }

    1;
}

#------------------------------------------

1;