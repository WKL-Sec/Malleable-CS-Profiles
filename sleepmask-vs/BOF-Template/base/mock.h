#include <cstdio>
#include <vector>
#include <string>

#include "../sleepmask.h"

// Macro to convert all args to correct size for corresponding architecture.
#define GateArg(x) (PVOID)(x)

namespace bof {
    const DWORD CsVersion = 0x041000;

    namespace profile {
        /**
         * Enum classes to mimic the stage block in the C2 profile.
         */
        enum class Allocator {
            VirtualAlloc,
            HeapAlloc,
            MapViewOfFile
        };
        enum class Obfuscate {
            False,
            True
        };
        enum class UseRWX {
            False,
            True
        };

        struct Stage {
            Allocator allocator;
            Obfuscate obfuscate;
            UseRWX useRWX;
            std::string module;
        };

        const Stage defaultStage = {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::True,
            .module = "",
        };
    }

    namespace mock {
        /**
         * Data container class used for packing BOF arguments.
         */
        class BofData {
        public:
            /**
             * Pack a variadic number of arguments.
             * Equivalent to the bof_pack function.
             * 
             * For example, bof_pack("isz", 1, 2, "hello")
             * -> pack<int, short, const char*>(1, 2, "hello")
             * 
             * @param ... arguments
             */
            template <typename... T>
            void pack(T &&...v)
            {
                ((insert(std::forward<T>(v))), ...);
            }

            /**
             * Add binary data to the argument buffer.
             * Equivalent to bof_pack("b", $data).
             *
             * @param buf A char pointer to the data
             * @param len A length to the data
             */
            void addData(const char *buf, std::size_t len);


            /**
             * << operator to allow an alternative way to build the argument buffer.
             * 
             * For example: args << 123 << 32;
             * 
             * @param container A BofData object
             * @param arg An argument
             */
            template <typename T>
            friend BofData &operator<<(BofData &container, T arg)
            {
                container.pack(arg);
                return container;
            }

            /**
             * Return a raw argument buffer.
             *
             * @return A char pointer of raw argument buffer
             */
            char* get();

            /**
             * Get the size of the argument buffer.
             *
             * @return A size of the argument buffer
             */
            int size();
        private:
            void append(const std::vector<char> &data);
            void insert(int v);
            void insert(short v);
            void insert(unsigned int v);
            void insert(unsigned short v);
            void insert(const char *v);
            void insert(const wchar_t *v);
            void insert(const std::vector<char>& data);

            std::vector<char> data;
        };

        /**
         * This structure holds the information about how the mock runner should
         * execute the sleepmask.
         */
        typedef struct {
            DWORD sleepTimeMs;
            bool runForever;
        } MockSleepMaskConfig;

        /**
         * Setup memory for a mock Beacon
         * 
         * The memory layout is created by mimicking Beacon's default reflective loader,
         * and the related C2 options
         * 
         * @param stage The applicable stage{} options
         * @return the mock Beacon memory structure
         */
        BEACON_INFO setupMockBeacon(const bof::profile::Stage& stage);
        FUNCTION_CALL createFunctionCallStructure(PVOID targetFunction, WinApi targetFunctionName, BOOL bMask, int numOfArgs, ...);
    }

    namespace output {
        /** 
         * Data structure to store a output from BOF
         */
        struct OutputEntry {
            /**
             * The callback type. E.g. CALLBACK_OUTPUT
             */
            int callbackType;

            /**
             * The output data
             */
            std::string output;

            /**
             * Equivalence overloading.
             * 
             * param other Another OutputEntry object
             */
            bool operator==(const OutputEntry& other) const {
                return callbackType == other.callbackType && output == other.output;
            }
        };

        /**
         * Returns the list of BOF outputs
         * 
         * @return A vector of OutputEntry objects
         */
        const std::vector<OutputEntry>& getOutputs();

        /**
         * Clear the currently stored BOF outputs
         */
        void reset();

        /**
         * Pretty print an OutputEntry object.
         * Required by the GoogleTest.
         * 
         * @param o An OutputEntry object
         * @param os An output stream
         */
        void PrintTo(const OutputEntry& o, std::ostream* os);
    }

    namespace valuestore {
        /**
         * Clear items in BOF Key/Value store
         */
        void reset();
    }

    namespace bud {
        /**
         * Clear the custom data buffer in Beacon User Data
         */
        void reset();

        /**
         * Set the custom data buffer in Beacon User Data
         *
         * @param data A pointer to custom data buffer
         */
        void set(const char* data);
    }

    /**
     * Execute a BOF with arguments
     *
     * @param entry BOF's entry point
     * @param ... arguments
     * @return A vector of OutputEntry objects
     */
    template <typename... T>
    std::vector<bof::output::OutputEntry> runMocked(void (*entry)(char*, int), T &&...v) {
        // Reset the global output container
        bof::output::reset();
        // Pack the arguments
        bof::mock::BofData args;
        args.pack(std::forward<T>(v)...);
        // Execute the entrypoint
        entry(args.get(), args.size());
        // Return the stored outputs
        return bof::output::getOutputs();
    }

    /**
     * Setup a mock-up Beacon and execute the sleepmask function once with the default .stage options and mock-up config.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc);

    /**
     * Setup a mock-up Beacon and execute the sleepmask function using a custom stage profile, and the default mock-up config.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @param stage the stage options
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, const bof::profile::Stage& stage);

    /**
     * Setup a mock-up Beacon and execute the sleepmask function using a custom stage profile and mock-up config.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @param stage the applicable stage{} options
     * @param config the mockup config
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, const bof::profile::Stage& stage, const bof::mock::MockSleepMaskConfig& config);

    /**
     * Execute the sleepmask.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @param sleepMaskInfo the pointer to the SLEEPMASK_INFO structure
     * @param functionCall the pointer to the FUNCTION_CALL structure
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, PSLEEPMASK_INFO sleepMaskInfo, PFUNCTION_CALL functionCall);

    /**
     * Setup a mock-up Beacon and execute the sleepmask function as Beacon Gate with the default stage block.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @param functionCall the pointer to FUNCTION_CALL structure
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedBeaconGate(SLEEPMASK_FUNC sleepMaskFunc, PFUNCTION_CALL functionCall);

    /**
     * Setup a mock-up Beacon and execute the sleepmask function as Beacon Gate with a custom stage profile.
     *
     * @param sleepMaskFunc the function pointer for the sleepmask
     * @param functionCall the pointer to FUNCTION_CALL structure
     * @param stage the stage options
     * @return A vector of OutputEntry objects
     */
    std::vector<bof::output::OutputEntry> runMockedBeaconGate(SLEEPMASK_FUNC sleepMaskFunc, PFUNCTION_CALL functionCall, const bof::profile::Stage& stage);
}