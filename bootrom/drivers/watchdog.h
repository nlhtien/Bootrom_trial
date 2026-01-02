/**
 * @file watchdog.h
 * @brief Watchdog Driver Interface (Stub)
 */

#ifndef WATCHDOG_H
#define WATCHDOG_H

/**
 * @brief Disable watchdog (driver function)
 */
void watchdog_disable_driver(void);

/**
 * @brief Reset watchdog
 */
void watchdog_reset(void);

#endif /* WATCHDOG_H */
