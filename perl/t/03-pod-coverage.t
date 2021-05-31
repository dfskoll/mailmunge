use Test::More;

use lib './lib';

eval "use Test::Pod::Coverage 1.00";
plan skip_all => "Test::Pod::Coverage 1.00 required for testing POD coverage" if $@;
plan skip_all => "POD coverage skipped as per \$SKIP_POD_COVERAGE" if $ENV{SKIP_POD_COVERAGE};
all_pod_coverage_ok({
        coverage_class => 'Pod::Coverage::CountParents',
	trustme => [],
        also_private => [],
                    });
