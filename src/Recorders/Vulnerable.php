<?php

declare(strict_types=1);

namespace HT\Pulse\Vulnerable\Recorders;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Process;
use Laravel\Pulse\Events\SharedBeat;
use Laravel\Pulse\Pulse;
use RuntimeException;

final class Vulnerable
{
    public string $listen = SharedBeat::class;

    public function __construct(protected Pulse $pulse)
    {
    }

    public function record(SharedBeat $event): void
    {
        if ($event->time->copy()->startOfDay()->diffInSeconds($event->time) > 10) {
            return;
        }

        // Throttle key on calendar day
        $throttleKey = 'shared-beat:composer-audit:' . $event->time->toDateString();

        // Prevent execution on same day
        if (!Cache::has($throttleKey)) {
            // Expire end of the day
            Cache::put($throttleKey, true, $event->time->copy()->endOfDay());
            $result = Process::run(command: 'composer audit -f json --locked');

            /**
             * @link https://github.com/composer/composer/issues/7323
             */
            if ($result->failed() && '' !== $result->errorOutput()) {
                throw new RuntimeException(message: 'Composer audit failed: ' . $result->errorOutput());
            }

            $this->pulse->set(type: 'vulnerable', key: 'result', value: $result->output());
        }
    }
}
