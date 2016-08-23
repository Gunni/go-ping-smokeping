package Smokeping::probes::GOPing;

=head1 301 Moved Permanently

This is a Smokeping probe module. Please use the command 

C<smokeping -man Smokeping::probes::GOPing>

to view the documentation or the command

C<smokeping -makepod Smokeping::probes::GOPing>

to generate the POD document.

=cut

use strict;
use base qw(Smokeping::probes::basefork); 

use Carp;
use IPC::Open3;
use diagnostics;
use strict;
use warnings;

sub pod_hash {
	return {
		name => <<DOC,
Smokeping::probes::GOPing - a Smokeping Probe.
DOC
		description => <<DOC,
TCP Pinger written in GOlang.
DOC
		authors => <<'DOC',
Gunnar Gudvardarson <gunnar.gudvardarson@advania.is>,
DOC
	};
}

sub new($$$)
{
    my $proto = shift;
    my $class = ref($proto) || $proto;
    my $self = $class->SUPER::new(@_);

    # no need for this if we run as a cgi
    unless ( $ENV{SERVER_SOFTWARE} ) {
    	# if you have to test the program output
	# or something like that, do it here
	# and bail out if necessary
    };

    return $self;
}

# This is where you should declare your probe-specific variables.
# The example shows the common case of checking the availability of
# the specified binary.

sub probevars {
	my $class = shift;
	return $class->_makevars($class->SUPER::probevars, {
		_mandatory => [ 'binary' ],
		binary => { 
			_doc => "The location of your go-ping binary.",
			_example => '/usr/local/bin/go-ping',
			_sub => sub { 
				my $val = shift;
				return undef;
			},
		},
		timeout => {
			 _re => '(\d*\.)?\d+',
			_example => 1,
			_default => 2,
			doc => <<DOC,
The go-ping "-t" parameter, in fractional seconds.

Timeout (in seconds) (default 2)
DOC
		},
		pings => {
			_re => '(\d*\.)?\d+',
			_example => 5,
			_default => 5,
			_doc => <<DOC,
The go-ping "-c" parameter, in whole numbers.

Number of connections to perform (0 = infinite) (default 20)
DOC
		},
		delay => {
			_re => '(\d*\.)?\d+',
			_example => .1,
			_default => 0,
			_doc => <<DOC,
The go-ping "-d" parameter, in fractional seconds.

Delay between sending each connection (in seconds) (default 0)
DOC
		},
		port => {
			_re => '(\d*\.)?\d+',
			_example => 30,
			_default => 80,
			_doc => <<DOC,
The go-ping "-p" parameter, in uint16.

Port to ping (default "80")
DOC
		},
		host => {
			_re => '([A-Za-z0-9\.])+',
			_example => "mbl.is",
			_doc => <<DOC,
The go-ping "-p" parameter, in uint16.

Port to ping (default "80")
DOC
		},
	});
}

# Here's the place for target-specific variables
sub targetvars {
	my $class = shift;
	return $class->_makevars($class->SUPER::targetvars, {
		timeout => {
			 _re => '(\d*\.)?\d+',
			_example => 1,
			_default => 2,
			doc => <<DOC,
The go-ping "-t" parameter, in fractional seconds.

Timeout (in seconds) (default 2)
DOC
		},
		pings => {
			_re => '(\d*\.)?\d+',
			_example => 5,
			_default => 5,
			_doc => <<DOC,
The go-ping "-c" parameter, in whole numbers.

Number of connections to perform (0 = infinite) (default 20)
DOC
		},
		delay => {
			_re => '(\d*\.)?\d+',
			_example => .1,
			_default => 0,
			_doc => <<DOC,
The go-ping "-d" parameter, in fractional seconds.

Delay between sending each connection (in seconds) (default 0)
DOC
		},
		port => {
			_re => '(\d*\.)?\d+',
			_example => 30,
			_default => 80,
			_doc => <<DOC,
The go-ping "-p" parameter, in uint16.

Port to ping (default "80")
DOC
		},
		host => {
			_re => '([A-Za-z0-9\.])+',
			_example => "mbl.is",
			_doc => <<DOC,
The go-ping "-p" parameter, in uint16.

Port to ping (default "80")
DOC
		},
	});
}

sub ProbeDesc($){
    my $self = shift;
    return "TCP handshakes";
}

# this is where the actual stuff happens
# you can access the probe-specific variables
# via the $self->{properties} hash and the
# target-specific variables via $target->{vars}

sub pingone ($){
	my $self = shift;
	my $target = shift;

	my $binary = $self->{properties}{binary};
	# my $weight = $target->{vars}{weight}
	my $count = $self->pings($target); # the number of pings for this targets

	# ping one target

	# execute a command and parse its output
	# you should return a sorted array of the measured latency times
	# it could go something like this:

	$self->do_debug('---------------------------------------------------------------');
	$self->do_debug(sprintf("binary: %s",  $self->{properties}{binary}));
	$self->do_debug(sprintf("count: %u",   $self->pings($target)));
	$self->do_debug(sprintf("delay: %f",   $target->{vars}{delay}));
	$self->do_debug(sprintf("port: %u",    $target->{vars}{port}));
	$self->do_debug(sprintf("timeout: %f", $target->{vars}{timeout}));
	$self->do_debug(sprintf("host: %s",    $target->{vars}{host}));
	$self->do_debug('---------------------------------------------------------------');

	my $cmd = sprintf("%s -c=%u -d=%f -p=%u -t=%f %s",
		$self->{properties}{binary},
		$self->pings($target),
		$target->{vars}{delay},
		$target->{vars}{port},
		$target->{vars}{timeout},
		$target->{vars}{host});
		
	$self->do_debug("Executing: $cmd");

	$self->do_debug('---------------------------------------------------------------');

	my @times;

	#open(P, "$cmd 2>&1 |") or croak("fork: $!");
	open(my $fh, '-|', $cmd) or croak("fork: $!");

	while (my $line = <$fh>) {
		my ($iteration, $destination, $result) = split(';', $line);

		my $forcefloat = $result + 0.0;

		#$self->do_debug(sprintf('Iteration: %u', $iteration));
		#$self->do_debug(sprintf('Destination: %s', $destination));
		#$self->do_debug(sprintf('Result: %f', $forcefloat));
		#$self->do_debug('---------------------------------------------------------------');

		if ($result eq "NaN") {
			# do nothing
			$self->do_debug(sprintf('LOSS!: %s', $line));
		}
		elsif ($forcefloat > 0.0 && $forcefloat <= $target->{vars}{timeout}) {
			push(@times, $forcefloat);
		}
		else {
			$self->do_debug(sprintf('LOSS?: %s', $line));
		}

		#/time: (\d+\.\d+)/ and push @times, $1;
	}

	close $fh;

	my @sorted = sort(@times);

	$self->do_debug(sprintf('NUM RESULTS: %u', scalar(@sorted)));

	return @sorted;
}

# That's all, folks!

1;
